from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import FileResponse, HttpResponseForbidden, Http404
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from tenants.models import UserTenantMembership
from assessments.models import Assessment, RiskItem, RiskTreatment
from findings.models import Finding
from .models import EvidenceDocument, EvidenceVersion
from .tasks import scan_file_clamav

@login_required
def document_library(request):
    """
    Renders the document library listing all active evidence documents
    and handles uploading new evidence documents.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if request.method == 'POST':
        # Retrieve form data
        name = request.POST.get('name')
        file = request.FILES.get('file')
        assessment_id = request.POST.get('assessment')
        risk_item_id = request.POST.get('risk_item')
        finding_id = request.POST.get('finding')
        treatment_id = request.POST.get('treatment')

        if not name or not file:
            messages.error(request, "Document name and file are required.")
            return redirect('document_library')

        # Limit file upload sizes (e.g., 20MB)
        if file.size > 20 * 1024 * 1024:
            messages.error(request, "File exceeds maximum size of 20MB.")
            return redirect('document_library')

        # Validate file extensions
        allowed_extensions = ['.pdf', '.docx', '.xlsx', '.csv', '.txt', '.png', '.jpg', '.jpeg']
        import os
        ext = os.path.splitext(file.name)[1].lower()
        if ext not in allowed_extensions:
            messages.error(request, f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}")
            return redirect('document_library')

        try:
            with transaction.atomic():
                # Resolve linked entities (ensuring tenant boundary checks)
                assessment = None
                if assessment_id:
                    if user_role == 'client':
                        assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant, client=user_client)
                    else:
                        assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)
                
                risk_item = None
                if risk_item_id:
                    if user_role == 'client':
                        risk_item = get_object_or_404(RiskItem, id=risk_item_id, assessment__tenant=tenant, assessment__client=user_client)
                    else:
                        risk_item = get_object_or_404(RiskItem, id=risk_item_id, assessment__tenant=tenant)
                
                finding = None
                if finding_id:
                    if user_role == 'client':
                        finding = get_object_or_404(Finding, id=finding_id, tenant=tenant, assessment__client=user_client)
                    else:
                        finding = get_object_or_404(Finding, id=finding_id, tenant=tenant)
                
                treatment = None
                if treatment_id:
                    if user_role == 'client':
                        treatment = get_object_or_404(RiskTreatment, id=treatment_id, risk_item__tenant=tenant, risk_item__assessment__client=user_client)
                    else:
                        treatment = get_object_or_404(RiskTreatment, id=treatment_id, risk_item__tenant=tenant)

                # Create logical document
                doc = EvidenceDocument.objects.create(
                    tenant=tenant,
                    name=name,
                    assessment=assessment,
                    risk_item=risk_item,
                    finding=finding,
                    treatment=treatment,
                    created_by=request.user
                )

                # Create initial version
                version = EvidenceVersion.objects.create(
                    document=doc,
                    version_number=1,
                    file=file,
                    file_name=file.name,
                    content_type=file.content_type,
                    file_size=file.size,
                    uploaded_by=request.user,
                    status='Pending'
                )

            # Trigger async malware scan via Celery
            scan_file_clamav.delay(version.id)
            messages.success(request, f"Document '{name}' uploaded and queued for security scanning.")
        except Exception as e:
            messages.error(request, f"Error uploading document: {e}")
        
        return redirect('document_library')

    # GET request: fetch documents and metadata for display
    documents = EvidenceDocument.objects.filter(tenant=tenant).select_related(
        'assessment', 'risk_item', 'finding', 'treatment', 'created_by'
    ).prefetch_related('versions')

    # Query fields for dropdown selections
    assessments = Assessment.objects.filter(tenant=tenant)
    risk_items = RiskItem.objects.filter(assessment__tenant=tenant)
    findings = Finding.objects.filter(tenant=tenant)
    treatments = RiskTreatment.objects.filter(risk_item__tenant=tenant)

    if user_role == 'client':
        documents = documents.filter(
            Q(assessment__client=user_client) |
            Q(risk_item__assessment__client=user_client) |
            Q(finding__assessment__client=user_client) |
            Q(treatment__risk_item__assessment__client=user_client) |
            Q(created_by=request.user)
        ).distinct()
        assessments = assessments.filter(client=user_client)
        risk_items = risk_items.filter(assessment__client=user_client)
        findings = findings.filter(assessment__client=user_client)
        treatments = treatments.filter(risk_item__assessment__client=user_client)

    return render(request, 'evidence/library.html', {
        'documents': documents,
        'assessments': assessments,
        'risk_items': risk_items,
        'findings': findings,
        'treatments': treatments,
    })

@login_required
def upload_new_version(request, doc_id):
    """
    Handles appending a new version to an existing EvidenceDocument.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if user_role == 'client':
        # Check if the document belongs to client's scope or was uploaded by client
        is_owner_or_related = EvidenceDocument.objects.filter(id=doc_id, tenant=tenant).filter(
            Q(assessment__client=user_client) |
            Q(risk_item__assessment__client=user_client) |
            Q(finding__assessment__client=user_client) |
            Q(treatment__risk_item__assessment__client=user_client) |
            Q(created_by=request.user)
        ).distinct().exists()
        if not is_owner_or_related:
            return HttpResponseForbidden("Permission denied. You cannot upload a new version to this document.")

    doc = get_object_or_404(EvidenceDocument, id=doc_id, tenant=tenant)

    if request.method == 'POST':
        file = request.FILES.get('file')
        if not file:
            messages.error(request, "Please select a file to upload.")
            return redirect('document_library')

        # Limit file size
        if file.size > 20 * 1024 * 1024:
            messages.error(request, "File exceeds maximum size of 20MB.")
            return redirect('document_library')

        # Validate extension
        import os
        allowed_extensions = ['.pdf', '.docx', '.xlsx', '.csv', '.txt', '.png', '.jpg', '.jpeg']
        ext = os.path.splitext(file.name)[1].lower()
        if ext not in allowed_extensions:
            messages.error(request, f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}")
            return redirect('document_library')

        try:
            with transaction.atomic():
                # Find current highest version number
                last_version = doc.versions.order_by('-version_number').first()
                next_version_num = (last_version.version_number + 1) if last_version else 1

                # Create the new version
                version = EvidenceVersion.objects.create(
                    document=doc,
                    version_number=next_version_num,
                    file=file,
                    file_name=file.name,
                    content_type=file.content_type,
                    file_size=file.size,
                    uploaded_by=request.user,
                    status='Pending'
                )

            # Queue scanning
            scan_file_clamav.delay(version.id)
            messages.success(request, f"New version (v{next_version_num}) uploaded and queued for security scanning.")
        except Exception as e:
            messages.error(request, f"Error uploading version: {e}")

    return redirect('document_library')

@login_required
def download_file(request, version_id):
    """
    Download view serving requested EvidenceVersion file.
    Blocks files that are not explicitly marked as Clean.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        return HttpResponseForbidden("Active tenant association required.")

    # Signed URL verification
    sig = request.GET.get('sig')
    from auditlog.signing import verify_signed_url
    if not sig or not verify_signed_url(request.path, sig):
        return HttpResponseForbidden("Access Denied: Invalid or expired signed URL.")

    user_role = getattr(request, 'user_role', None)
    user_client = getattr(request, 'user_client', None)

    if user_role == 'client':
        # Check if the document version belongs to client's scope or was uploaded by client
        is_owner_or_related = EvidenceVersion.objects.filter(id=version_id, document__tenant=tenant).filter(
            Q(document__assessment__client=user_client) |
            Q(document__risk_item__assessment__client=user_client) |
            Q(document__finding__assessment__client=user_client) |
            Q(document__treatment__risk_item__assessment__client=user_client) |
            Q(document__created_by=request.user)
        ).distinct().exists()
        if not is_owner_or_related:
            return HttpResponseForbidden("Permission Denied: You do not have access to this document version.")

    version = get_object_or_404(EvidenceVersion, id=version_id, document__tenant=tenant)

    # Security check: Quarantine block
    if version.status != 'Clean':
        logger_name = f"evidence.security.{tenant.id}"
        import logging
        logging.getLogger(logger_name).warning(
            f"Blocked unauthorized file download attempt. Version: {version.id}, Status: {version.status}, User: {request.user.email}"
        )
        return HttpResponseForbidden(
            f"Access Denied: This file is currently {version.status} and cannot be downloaded."
        )

    try:
        response = FileResponse(version.file.open('rb'), content_type=version.content_type)
        response['Content-Disposition'] = f'attachment; filename="{version.file_name}"'
        
        # Log Audit event
        from auditlog.utils import log_audit_event
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='EVIDENCE',
            action='DOWNLOAD',
            payload={
                'evidence_document_id': version.document.id,
                'evidence_version_id': version.id,
                'file_name': version.file_name,
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        return response
    except FileNotFoundError:
        raise Http404("File not found on storage server.")

@login_required
def delete_document(request, doc_id):
    """
    Soft-deletes a logical evidence document.
    Restricted to admin and owner user roles in the tenant.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    user_role = getattr(request, 'user_role', None)
    if user_role == 'client':
        messages.error(request, "Permission Denied: Client users cannot delete evidence documents.")
        return redirect('document_library')

    doc = get_object_or_404(EvidenceDocument, id=doc_id, tenant=tenant)

    # RBAC logic verification: Check if admin/owner
    is_authorized = UserTenantMembership.objects.filter(
        user=request.user,
        tenant=tenant,
        role__in=['admin', 'owner']
    ).exists()

    if not is_authorized:
        messages.error(request, "Permission Denied: Only Admins or Owners can delete evidence documents.")
        return redirect('document_library')

    try:
        doc.delete()
        from auditlog.utils import log_audit_event
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='EVIDENCE',
            action='DELETE',
            payload={
                'evidence_document_id': doc.id,
                'name': doc.name,
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )
        messages.success(request, f"Document '{doc.name}' was successfully deleted.")
    except Exception as e:
        messages.error(request, f"Error deleting document: {e}")

    return redirect('document_library')
