import re
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.contrib import messages
from django.db import transaction
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.urls import reverse

from auditlog.models import AuditEvent
from tenants.models import Client
from assessments.models import Assessment, RiskItem, RiskTreatment, TemplateAssessment
from assessments.workflows import evidence_is_clean, scope_evidence_for_user
from findings.models import Finding
from evidence.models import EvidenceDocument, EvidenceVersion
from evidence.tasks import scan_file_clamav
from .models import Comment, EvidenceRequest, Notification, CollaborationActivity

User = get_user_model()

def log_audit_event(tenant, user, event_type, action, payload):
    """
    Helper to log an immutable audit event to the ledger.
    """
    try:
        AuditEvent.objects.create(
            tenant=tenant,
            user=user,
            event_type=event_type,
            action=action,
            payload=payload
        )
    except Exception as e:
        # Don't break execution if auditing fails, but log it
        print(f"Audit log failed: {e}")

def create_activity_feed_entry(tenant, user, action_type, description):
    """
    Helper to log an activity feed entry.
    """
    CollaborationActivity.objects.create(
        tenant=tenant,
        user=user,
        action_type=action_type,
        description=description
    )

def parse_mentions_and_notify(text, author, tenant, url, item_title):
    """
    Parses @username or @email patterns in comment text and notifies users.
    """
    if not text:
        return
        
    # Find email mentions like @john.doe@example.com
    email_mentions = re.findall(r'@([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', text)
    # Find username mentions like @john_doe
    username_mentions = re.findall(r'@([a-zA-Z0-9_.-]+)', text)
    usernames = [u for u in username_mentions if '@' not in u and '.' not in u]

    notified_users = set()

    for email in email_mentions:
        u = User.objects.filter(email=email, memberships__tenant=tenant).first()
        if u and u != author:
            notified_users.add(u)

    for username in usernames:
        u = User.objects.filter(username=username, memberships__tenant=tenant).first()
        if u and u != author:
            notified_users.add(u)

    for u in notified_users:
        Notification.objects.create(
            tenant=tenant,
            recipient=u,
            title="You were mentioned",
            message=f"{author.email} mentioned you in discussion on '{item_title}': \"{text[:60]}...\"",
            url=url
        )

@login_required
@require_POST
def add_comment(request):
    """
    POST endpoint to add a comment to any collaboration target entity.
    """
    tenant = request.tenant
    user = request.user
    
    entity_type = request.POST.get('entity_type')
    entity_id = request.POST.get('entity_id')
    text = request.POST.get('text', '').strip()
    parent_id = request.POST.get('parent_id')
    next_url = request.POST.get('next', 'dashboard')

    if not text or not entity_type or not entity_id:
        messages.error(request, "Comment text is required.")
        return redirect(next_url)

    comment = Comment(tenant=tenant, user=user, text=text)
    item_title = "Assessor Workspace"
    url = next_url

    # Check and attach correct entity target
    if entity_type == 'assessment':
        qs = Assessment.objects.filter(id=entity_id, tenant=tenant)
        if getattr(request, 'user_role', None) == 'client':
            qs = qs.filter(client=getattr(request, 'user_client', None))
        comment.assessment = get_object_or_404(qs)
        item_title = comment.assessment.name
    elif entity_type == 'risk_item':
        qs = RiskItem.objects.filter(id=entity_id, assessment__tenant=tenant)
        if getattr(request, 'user_role', None) == 'client':
            qs = qs.filter(assessment__client=getattr(request, 'user_client', None))
        comment.risk_item = get_object_or_404(qs)
        item_title = comment.risk_item.asset_name
    elif entity_type == 'finding':
        qs = Finding.objects.filter(id=entity_id, tenant=tenant)
        if getattr(request, 'user_role', None) == 'client':
            qs = qs.filter(assessment__client=getattr(request, 'user_client', None))
        comment.finding = get_object_or_404(qs)
        item_title = comment.finding.title
    elif entity_type == 'treatment':
        qs = RiskTreatment.objects.filter(id=entity_id, risk_item__assessment__tenant=tenant)
        if getattr(request, 'user_role', None) == 'client':
            qs = qs.filter(risk_item__assessment__client=getattr(request, 'user_client', None))
        comment.treatment = get_object_or_404(qs)
        item_title = f"Treatment: {comment.treatment.risk_item.asset_name}"
    elif entity_type == 'template_assessment':
        qs = TemplateAssessment.objects.filter(id=entity_id, tenant=tenant)
        if getattr(request, 'user_role', None) == 'client':
            qs = qs.filter(client=getattr(request, 'user_client', None))
        comment.template_assessment = get_object_or_404(qs)
        item_title = comment.template_assessment.name
    else:
        messages.error(request, "Invalid comment target.")
        return redirect(next_url)

    # Nesting parent
    if parent_id:
        parent_comment = get_object_or_404(Comment, id=parent_id, tenant=tenant)
        comment.parent = parent_comment

    with transaction.atomic():
        comment.save()
        
        # Log Audit event
        log_payload = {
            'comment_id': comment.id,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'parent_id': parent_id,
            'text_length': len(text)
        }
        log_audit_event(tenant, user, 'COLLABORATION', 'CREATE', log_payload)
        
        # Log timeline activity
        create_activity_feed_entry(
            tenant, user, 'comment_created', 
            f"Added comment on {entity_type} '{item_title}'"
        )
        
        # Notify user if they are replying to another comment
        if parent_id and parent_comment.user != user:
            Notification.objects.create(
                tenant=tenant,
                recipient=parent_comment.user,
                title="New reply received",
                message=f"{user.email} replied to your comment: \"{text[:50]}...\"",
                url=url
            )

        # Parse mentions
        parse_mentions_and_notify(text, user, tenant, url, item_title)

    messages.success(request, "Comment posted successfully.")
    return redirect(next_url)


@login_required
def notifications_list(request):
    """
    Renders user's notifications center.
    """
    tenant = request.tenant
    notifications = Notification.objects.filter(tenant=tenant, recipient=request.user)
    return render(request, 'collaboration/notifications.html', {
        'notifications': notifications
    })


@login_required
def api_unread_notifications(request):
    """
    JSON API returning unread count and latest unread logs.
    """
    tenant = request.tenant
    if not tenant:
        return JsonResponse({'count': 0, 'notifications': []})
        
    unread = Notification.objects.filter(tenant=tenant, recipient=request.user, is_read=False)[:5]
    unread_count = Notification.objects.filter(tenant=tenant, recipient=request.user, is_read=False).count()
    
    data = []
    for n in unread:
        data.append({
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'url': n.url,
            'created_at': n.created_at.strftime('%Y-%m-%d %H:%M')
        })
        
    return JsonResponse({
        'count': unread_count,
        'notifications': data
    })


@login_required
@require_POST
def mark_notification_read(request, notif_id):
    """
    Marks a specific notification as read.
    """
    tenant = request.tenant
    notif = get_object_or_404(Notification, id=notif_id, tenant=tenant, recipient=request.user)
    notif.is_read = True
    notif.save()
    return JsonResponse({'status': 'success'})


@login_required
@require_POST
def mark_all_notifications_read(request):
    """
    Marks all notifications for active user as read.
    """
    tenant = request.tenant
    Notification.objects.filter(tenant=tenant, recipient=request.user, is_read=False).update(is_read=True)
    return JsonResponse({'status': 'success'})


@login_required
def evidence_requests_list(request):
    """
    Lists evidence requests for assessors/reviewers or clients.
    """
    tenant = request.tenant
    user = request.user
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if user_role == 'client':
        # Clients see only their requests
        requests = EvidenceRequest.objects.filter(tenant=tenant, client=user_client).select_related(
            'assessment', 'risk_item', 'finding', 'requested_by', 'submitted_evidence'
        )
    else:
        # Assessors see all requests
        requests = EvidenceRequest.objects.filter(tenant=tenant).select_related(
            'client', 'assessment', 'risk_item', 'finding', 'requested_by', 'submitted_evidence'
        )

    # Load context options for request creation
    clients = Client.objects.filter(tenant=tenant)
    assessments = Assessment.objects.filter(tenant=tenant)
    risk_items = RiskItem.objects.filter(assessment__tenant=tenant)
    findings = Finding.objects.filter(tenant=tenant)

    if user_role == 'client':
        assessments = assessments.filter(client=user_client)
        risk_items = risk_items.filter(assessment__client=user_client)
        findings = findings.filter(assessment__client=user_client)

    # Activity timeline feed for this tenant
    activities = CollaborationActivity.objects.filter(tenant=tenant).select_related('user')[:20]

    # Handle Request Creation POST
    if request.method == 'POST':
        if user_role == 'client':
            messages.error(request, "Permission denied. Client users cannot create evidence requests.")
            return redirect('evidence_requests_list')

        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        client_id = request.POST.get('client')
        assessment_id = request.POST.get('assessment') or None
        risk_item_id = request.POST.get('risk_item') or None
        finding_id = request.POST.get('finding') or None

        if not title or not client_id:
            messages.error(request, "Title and Client are required.")
            return redirect('evidence_requests_list')

        client_obj = get_object_or_404(Client, id=client_id, tenant=tenant)
        req = EvidenceRequest(
            tenant=tenant,
            title=title,
            description=description,
            client=client_obj,
            requested_by=user,
            status='Pending'
        )

        if assessment_id:
            req.assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant, client=client_obj)
        if risk_item_id:
            req.risk_item = get_object_or_404(RiskItem, id=risk_item_id, assessment__tenant=tenant, assessment__client=client_obj)
        if finding_id:
            req.finding = get_object_or_404(Finding, id=finding_id, tenant=tenant, assessment__client=client_obj)

        with transaction.atomic():
            req.save()
            
            # Log audit & activity
            log_payload = {
                'request_id': req.id,
                'title': title,
                'client_id': client_obj.id,
                'assessment_id': assessment_id
            }
            log_audit_event(tenant, user, 'COLLABORATION', 'CREATE', log_payload)
            create_activity_feed_entry(tenant, user, 'request_created', f"Requested evidence '{title}' from {client_obj.name}")

            # Notify client users
            client_users = User.objects.filter(memberships__tenant=tenant, memberships__role='client', memberships__client=client_obj)
            for cu in client_users:
                Notification.objects.create(
                    tenant=tenant,
                    recipient=cu,
                    title="New Evidence Request",
                    message=f"Assessors requested documentation for '{title}'. Please respond.",
                    url=reverse('evidence_requests_list')
                )

        messages.success(request, f"Evidence request '{title}' dispatched successfully.")
        return redirect('evidence_requests_list')

    return render(request, 'collaboration/requests_list.html', {
        'requests': requests,
        'clients': clients,
        'assessments': assessments,
        'risk_items': risk_items,
        'findings': findings,
        'activities': activities,
        'user_role': user_role
    })


@login_required
@require_POST
def submit_evidence_response(request, request_id):
    """
    POST endpoint enabling client users to fulfill/submit evidence requests.
    """
    tenant = request.tenant
    user = request.user
    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    req = get_object_or_404(EvidenceRequest, id=request_id, tenant=tenant)

    # Restriction: only client company memberships can respond
    if user_role != 'client':
        messages.error(request, "Permission denied. Only client users can submit evidence responses.")
        return redirect('evidence_requests_list')

    if req.client != user_client:
        messages.error(request, "Permission denied. You cannot respond to requests for other client companies.")
        return redirect('evidence_requests_list')

    client_response = request.POST.get('client_response', '').strip()
    evidence_id = request.POST.get('evidence_id') # Selected existing document
    file = request.FILES.get('file') # Uploaded new document

    if not evidence_id and not file:
        messages.error(request, "Please upload a file or select an existing document.")
        return redirect('evidence_requests_list')

    with transaction.atomic():
        doc = None
        if file:
            # 1. Limit file size
            if file.size > 20 * 1024 * 1024:
                messages.error(request, "File exceeds maximum size of 20MB.")
                return redirect('evidence_requests_list')

            # 2. Upload file & build EvidenceDocument / Version
            import os
            name = f"Evidence for Request: {req.title}"
            doc = EvidenceDocument.objects.create(
                tenant=tenant,
                name=name,
                created_by=user,
                assessment=req.assessment,
                risk_item=req.risk_item,
                finding=req.finding
            )

            # File versioning
            version = EvidenceVersion.objects.create(
                document=doc,
                version_number=1,
                file=file,
                file_name=file.name,
                file_size=file.size,
                content_type=file.content_type,
                uploaded_by=user,
                status='Pending'
            )

            # Compute SHA-256 hash on version save
            hasher = hashlib.sha256()
            for chunk in file.chunks():
                hasher.update(chunk)
            version.sha256_hash = hasher.hexdigest()
            version.save()

            # Trigger async malware scan
            scan_file_clamav.delay(version.id)
        else:
            doc = get_object_or_404(
                scope_evidence_for_user(
                    EvidenceDocument.objects.filter(id=evidence_id, tenant=tenant),
                    request,
                )
            )

        req.submitted_evidence = doc
        req.client_response = client_response
        req.status = 'Submitted'
        req.save()

        # Log WORM audit entry
        log_payload = {
            'request_id': req.id,
            'submitted_evidence_id': doc.id,
            'client_response': client_response
        }
        log_audit_event(tenant, user, 'COLLABORATION', 'UPDATE', log_payload)

        # Log activity timeline feed
        create_activity_feed_entry(tenant, user, 'request_submitted', f"Submitted evidence for request '{req.title}'")

        # Notify requesting assessor user
        Notification.objects.create(
            tenant=tenant,
            recipient=req.requested_by,
            title="Evidence Submitted",
            message=f"Client '{req.client.name}' uploaded evidence response for request '{req.title}'. Please review.",
            url=reverse('evidence_requests_list')
        )

    messages.success(request, "Response submitted successfully and queued for verification scanning.")
    return redirect('evidence_requests_list')

# Import hashlib inside submit_evidence_response context if not imported
import hashlib


@login_required
@require_POST
def approve_reject_evidence_request(request, request_id):
    """
    POST endpoint for Assessors/Reviewers to approve or reject a client evidence submission.
    """
    tenant = request.tenant
    user = request.user
    user_role = getattr(request, 'user_role', None)

    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot approve or reject evidence requests.")
        return redirect('evidence_requests_list')

    req = get_object_or_404(EvidenceRequest, id=request_id, tenant=tenant)
    action = request.POST.get('action') # approve or reject
    rejection_notes = request.POST.get('rejection_notes', '').strip()

    if action == 'approve':
        if not req.submitted_evidence:
            messages.error(request, "No submitted evidence found to approve.")
            return redirect('evidence_requests_list')
        if not evidence_is_clean(req.submitted_evidence):
            messages.error(request, "Submitted evidence cannot be approved until its latest version has passed malware scanning.")
            return redirect('evidence_requests_list')

        with transaction.atomic():
            req.status = 'Approved'
            req.rejection_notes = ""
            req.save()

            # Link evidence document to target entities
            doc = req.submitted_evidence
            if req.assessment:
                doc.assessment = req.assessment
            if req.risk_item:
                doc.risk_item = req.risk_item
            if req.finding:
                doc.finding = req.finding
            doc.save()

            # Log Audit Event
            log_payload = {
                'request_id': req.id,
                'status': 'Approved',
                'linked_evidence_id': doc.id
            }
            log_audit_event(tenant, user, 'COLLABORATION', 'UPDATE', log_payload)

            # Timeline activity
            create_activity_feed_entry(tenant, user, 'request_approved', f"Approved evidence for request '{req.title}'")

            # Notify submitting client users
            client_users = User.objects.filter(memberships__tenant=tenant, memberships__role='client', memberships__client=req.client)
            for cu in client_users:
                Notification.objects.create(
                    tenant=tenant,
                    recipient=cu,
                    title="Evidence Request Approved",
                    message=f"Assessors approved your response for request '{req.title}'.",
                    url=reverse('evidence_requests_list')
                )

        messages.success(request, f"Evidence request '{req.title}' has been approved and linked.")

    elif action == 'reject':
        with transaction.atomic():
            req.status = 'Rejected'
            req.rejection_notes = rejection_notes
            req.save()

            # Log Audit Event
            log_payload = {
                'request_id': req.id,
                'status': 'Rejected',
                'rejection_notes': rejection_notes
            }
            log_audit_event(tenant, user, 'COLLABORATION', 'UPDATE', log_payload)

            # Timeline activity
            create_activity_feed_entry(tenant, user, 'request_rejected', f"Rejected evidence for request '{req.title}'")

            # Notify client users of rejection
            client_users = User.objects.filter(memberships__tenant=tenant, memberships__role='client', memberships__client=req.client)
            for cu in client_users:
                Notification.objects.create(
                    tenant=tenant,
                    recipient=cu,
                    title="Evidence Request Rejected",
                    message=f"Assessors rejected your response for '{req.title}': {rejection_notes}",
                    url=reverse('evidence_requests_list')
                )

        messages.success(request, f"Evidence request '{req.title}' has been rejected.")

    else:
        messages.error(request, "Invalid request action.")

    return redirect('evidence_requests_list')
