from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db import transaction
from django.db.models import Q
from accounts.models import User
from assessments.models import Assessment, RiskItem
from evidence.models import EvidenceDocument
from .models import Finding, Recommendation
from tenants.models import UserTenantMembership
from collaboration.views import log_audit_event, create_activity_feed_entry

@login_required
def finding_list(request):
    """
    Renders the Findings Register showing all findings for the active tenant.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    findings = Finding.objects.filter(tenant=tenant).select_related(
        'assessment', 'risk_item', 'assignee'
    ).prefetch_related('recommendations', 'evidence')

    if user_role == 'client':
        findings = findings.filter(assessment__client=user_client)

    return render(request, 'findings/finding_list.html', {
        'findings': findings,
        'user_role': user_role,
    })

@login_required
def finding_edit(request, finding_id=None):
    """
    Unified view to create a new Finding or edit an existing one,
    including its inline Recommendation details.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    finding = None
    recommendation = None
    if finding_id:
        if user_role == 'client':
            finding = get_object_or_404(Finding, id=finding_id, tenant=tenant, assessment__client=user_client)
        else:
            finding = get_object_or_404(Finding, id=finding_id, tenant=tenant)
        recommendation = finding.recommendations.first()
    elif user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot create findings.")
        return redirect('finding_list')

    if request.method == 'POST':
        if user_role == 'client':
            # Clients can respond to findings by submitting/linking evidence
            evidence_ids = request.POST.getlist('evidence')
            with transaction.atomic():
                valid_evidence = EvidenceDocument.objects.filter(id__in=evidence_ids, tenant=tenant).filter(
                    Q(assessment__client=user_client) |
                    Q(risk_item__assessment__client=user_client) |
                    Q(finding__assessment__client=user_client) |
                    Q(treatment__risk_item__assessment__client=user_client) |
                    Q(created_by=request.user)
                ).distinct()
                finding.evidence.set(valid_evidence)
                finding.save()
                
                # Audit log WORM entry
                log_payload = {
                    'finding_id': finding.id,
                    'evidence_ids': list(valid_evidence.values_list('id', flat=True))
                }
                log_audit_event(tenant, request.user, 'COLLABORATION', 'UPDATE', log_payload)
                create_activity_feed_entry(tenant, request.user, 'finding_updated', f"Client updated evidence links for finding '{finding.title}'")
                
                messages.success(request, "Finding response and evidence link updated successfully.")
            return redirect('finding_list')
        title = request.POST.get('title')
        description = request.POST.get('description', '')
        severity = request.POST.get('severity', 'Medium')
        status = request.POST.get('status', 'Open')
        assessment_id = request.POST.get('assessment')
        risk_item_id = request.POST.get('risk_item') or None
        assignee_id = request.POST.get('assignee') or None
        due_date = request.POST.get('due_date') or None
        evidence_ids = request.POST.getlist('evidence')

        # Recommendation fields
        rec_text = request.POST.get('rec_text', '')
        rec_priority = request.POST.get('rec_priority', 'Medium')
        rec_effort = request.POST.get('rec_effort', 'Medium')
        rec_cost = request.POST.get('rec_cost_estimate') or None

        if not title or not assessment_id:
            messages.error(request, "Title and Linked Assessment are required.")
        else:
            try:
                with transaction.atomic():
                    # Validate Linked Assessment exists in tenant
                    assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)
                    
                    # Validate Linked RiskItem (if selected) is in assessment
                    risk_item = None
                    if risk_item_id:
                        risk_item = get_object_or_404(RiskItem, id=risk_item_id, assessment=assessment)
                    
                    # Validate Assignee (if selected) is member of tenant
                    assignee = None
                    if assignee_id:
                        assignee = get_object_or_404(User, id=assignee_id, memberships__tenant=tenant)

                    if not finding:
                        finding = Finding(tenant=tenant)

                    finding.title = title
                    finding.description = description
                    finding.severity = severity
                    finding.status = status
                    finding.assessment = assessment
                    finding.risk_item = risk_item
                    finding.assignee = assignee
                    finding.due_date = due_date
                    finding.save()

                    # Set ManyToMany evidence files
                    if evidence_ids:
                        valid_evidence = EvidenceDocument.objects.filter(id__in=evidence_ids, tenant=tenant).filter(
                            Q(assessment__client=assessment.client) |
                            Q(risk_item__assessment__client=assessment.client) |
                            Q(finding__assessment__client=assessment.client) |
                            Q(treatment__risk_item__assessment__client=assessment.client) |
                            Q(assessment__isnull=True, risk_item__isnull=True, finding__isnull=True, treatment__isnull=True)
                        ).distinct()
                        finding.evidence.set(valid_evidence)
                    else:
                        finding.evidence.clear()

                    # Create or update inline recommendation details
                    if rec_text.strip():
                        if not recommendation:
                            recommendation = Recommendation(tenant=tenant, finding=finding)
                        recommendation.text = rec_text
                        recommendation.priority = rec_priority
                        recommendation.effort = rec_effort
                        
                        if rec_cost:
                            try:
                                recommendation.cost_estimate = float(rec_cost)
                            except ValueError:
                                recommendation.cost_estimate = None
                        else:
                            recommendation.cost_estimate = None
                        recommendation.save()
                    elif recommendation:
                        # If recommendation text was cleared, soft-delete it
                        recommendation.delete()

                messages.success(request, f"Finding '{title}' successfully saved.")
                return redirect('finding_list')
            except Exception as e:
                messages.error(request, f"Error saving finding: {e}")

    # Query details to build selections in template
    assessments = Assessment.objects.filter(tenant=tenant)
    risk_items = RiskItem.objects.filter(assessment__tenant=tenant)
    evidence_docs = EvidenceDocument.objects.filter(tenant=tenant)
    assignees = User.objects.filter(memberships__tenant=tenant).distinct()

    if user_role == 'client':
        assessments = assessments.filter(client=user_client)
        risk_items = risk_items.filter(assessment__client=user_client)
        evidence_docs = evidence_docs.filter(
            Q(assessment__client=user_client) |
            Q(risk_item__assessment__client=user_client) |
            Q(finding__assessment__client=user_client) |
            Q(treatment__risk_item__assessment__client=user_client) |
            Q(created_by=request.user)
        ).distinct()

    # Pre-populate linked evidence IDs
    linked_evidence_ids = list(finding.evidence.values_list('id', flat=True)) if finding else []

    # Fetch comments thread for discussion on findings
    comments = None
    if finding:
        comments = finding.comments.filter(parent=None).select_related('user').prefetch_related('replies__user')

    return render(request, 'findings/finding_edit.html', {
        'finding': finding,
        'recommendation': recommendation,
        'assessments': assessments,
        'risk_items': risk_items,
        'evidence_docs': evidence_docs,
        'assignees': assignees,
        'linked_evidence_ids': linked_evidence_ids,
        'severity_choices': Finding.SEVERITY_CHOICES,
        'status_choices': Finding.STATUS_CHOICES,
        'priority_choices': Recommendation.PRIORITY_CHOICES,
        'effort_choices': Recommendation.EFFORT_CHOICES,
        'comments': comments,
        'user_role': user_role,
    })

@login_required
def finding_delete(request, finding_id):
    """
    Soft-deletes a Finding.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission denied. Client users cannot delete findings.")
        return redirect('finding_list')

    finding = get_object_or_404(Finding, id=finding_id, tenant=tenant)
    try:
        finding.delete()
        messages.success(request, f"Finding '{finding.title}' successfully deleted.")
    except Exception as e:
        messages.error(request, f"Error deleting finding: {e}")

    return redirect('finding_list')
