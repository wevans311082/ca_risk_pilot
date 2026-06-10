from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import FileResponse, HttpResponseForbidden, Http404
from django.db import transaction
from django.utils import timezone
from tenants.models import UserTenantMembership
from assessments.models import Assessment
from .models import ReportDocument, ReportVersion, ReportDownloadHistory
from .tasks import generate_report_task

@login_required
def reporting_center(request):
    """
    Renders the Reporting Center dashboard containing generated report tables,
    version audit history, download stats, and quick-generate controls.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    # Fetch all assessments in the tenant for dropdown/generation
    assessments = Assessment.objects.filter(tenant=tenant).select_related('client')

    # Fetch all logical report documents for the tenant
    reports = ReportDocument.objects.filter(tenant=tenant).select_related('assessment').prefetch_related(
        'versions', 'versions__downloads'
    )

    # Compile type and format choices to build select dropdowns in template
    report_types = ReportDocument.REPORT_TYPE_CHOICES
    file_formats = ReportDocument.FILE_FORMAT_CHOICES

    return render(request, 'reporting/reporting_center.html', {
        'assessments': assessments,
        'reports': reports,
        'report_types': report_types,
        'file_formats': file_formats,
    })

@login_required
def generate_report(request):
    """
    POST handler to trigger new report generations or append new versions
    (regeneration) to existing documents.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    if request.method == 'POST':
        assessment_id = request.POST.get('assessment')
        report_type = request.POST.get('report_type')
        file_format = request.POST.get('file_format')

        if not assessment_id or not report_type or not file_format:
            messages.error(request, "All generation fields (Assessment, Type, Format) are required.")
            return redirect('reporting_center')

        # Verify assessment belongs to active tenant
        assessment = get_object_or_404(Assessment, id=assessment_id, tenant=tenant)

        try:
            with transaction.atomic():
                # Find or create logical document
                doc, created = ReportDocument.objects.get_or_create(
                    tenant=tenant,
                    assessment=assessment,
                    report_type=report_type,
                    file_format=file_format,
                    defaults={'created_by': request.user}
                )

                # Determine next version number
                last_version = doc.versions.order_by('-version_number').first()
                next_version_num = (last_version.version_number + 1) if last_version else 1

                # Create report version in Pending state
                version = ReportVersion.objects.create(
                    document=doc,
                    version_number=next_version_num,
                    status='Pending',
                    generated_by=request.user
                )

            # Trigger background Celery generation & malware scan tasks
            generate_report_task.delay(version.id)
            messages.success(request, f"Generation of '{doc.get_report_type_display()} ({doc.file_format})' queued successfully.")

        except Exception as e:
            messages.error(request, f"Failed to queue report generation: {e}")

    # Redirect back to where user came from, or dashboard as fallback
    next_url = request.META.get('HTTP_REFERER', 'reporting_center')
    # Prevent infinite redirects if referee is this view
    if 'generate' in next_url:
        next_url = 'reporting_center'
    return redirect(next_url)

@login_required
def download_report(request, version_id):
    """
    Download view serving clean reports and logging access history.
    Blocks files that are not verified clean by ClamAV.
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        return HttpResponseForbidden("Active tenant association required.")

    # Signed URL verification
    sig = request.GET.get('sig')
    from auditlog.signing import verify_signed_url
    if not sig or not verify_signed_url(request.path, sig):
        return HttpResponseForbidden("Access Denied: Invalid or expired signed URL.")

    version = get_object_or_404(ReportVersion, id=version_id, document__tenant=tenant)

    # Security check: Quarantine block
    if version.status != 'Clean':
        import logging
        logger_name = f"reporting.security.{tenant.id}"
        logging.getLogger(logger_name).warning(
            f"Blocked unauthorized report download attempt. Version: {version.id}, Status: {version.status}, User: {request.user.email}"
        )
        return HttpResponseForbidden(
            f"Access Denied: This report file is currently {version.get_status_display()} and cannot be downloaded."
        )

    if not version.file:
        raise Http404("Report file payload not found in storage.")

    try:
        # Create Download History audit record
        ReportDownloadHistory.objects.create(
            version=version,
            downloaded_by=request.user
        )

        # Log AuditEvent
        from auditlog.utils import log_audit_event
        log_audit_event(
            tenant=tenant,
            user=request.user,
            event_type='REPORT',
            action='DOWNLOAD',
            payload={
                'report_document_id': version.document.id,
                'report_version_id': version.id,
                'report_type': version.document.report_type,
                'file_format': version.document.file_format,
            },
            ip_address=request.META.get('REMOTE_ADDR')
        )

        response = FileResponse(version.file.open('rb'), content_type="application/octet-stream")
        response['Content-Disposition'] = f'attachment; filename="{version.file.name.split("/")[-1]}"'
        return response
    except FileNotFoundError:
        raise Http404("Physical report file not found on storage server.")

@login_required
def delete_report(request, doc_id):
    """
    Soft-deletes a logical ReportDocument (restricted to admin/owner roles).
    """
    tenant = getattr(request, 'tenant', None)
    if not tenant:
        messages.error(request, "No active tenant association found.")
        return redirect('login')

    doc = get_object_or_404(ReportDocument, id=doc_id, tenant=tenant)

    # RBAC logic verification: Check if admin/owner
    is_authorized = UserTenantMembership.objects.filter(
        user=request.user,
        tenant=tenant,
        role__in=['admin', 'owner']
    ).exists()

    if not is_authorized:
        messages.error(request, "Permission Denied: Only Admins or Owners can delete report records.")
    else:
        try:
            doc.delete()
            from auditlog.utils import log_audit_event
            log_audit_event(
                tenant=tenant,
                user=request.user,
                event_type='REPORT',
                action='DELETE',
                payload={
                    'report_document_id': doc.id,
                    'report_type': doc.report_type,
                },
                ip_address=request.META.get('REMOTE_ADDR')
            )
            messages.success(request, f"Report '{doc}' successfully deleted.")
        except Exception as e:
            messages.error(request, f"Error deleting report: {e}")

    # Redirect back to referee
    return redirect(request.META.get('HTTP_REFERER', 'reporting_center'))
