import logging
import traceback
from celery import shared_task
from django.core.files.base import ContentFile
from django.utils import timezone
from auditlog.models import AuditEvent
from evidence.tasks import scan_file_stream
from .models import ReportVersion
from .generators.pdf import generate_pdf_report
from .generators.docx import generate_docx_report
from .generators.xlsx import generate_xlsx_report

logger = logging.getLogger(__name__)

@shared_task
def generate_report_task(report_version_id):
    """
    Celery task to compile assessment risk data and output report binaries
    for PDF, DOCX, and XLSX formats.
    """
    try:
        version = ReportVersion.objects.get(id=report_version_id)
    except ReportVersion.DoesNotExist:
        logger.error(f"ReportVersion {report_version_id} not found.")
        return f"ReportVersion {report_version_id} not found."

    doc_meta = version.document
    assessment = doc_meta.assessment
    file_format = doc_meta.file_format.upper()
    report_type = doc_meta.report_type

    try:
        # Generate binary payload
        if file_format == 'PDF':
            binary_data = generate_pdf_report(assessment, report_type)
        elif file_format == 'DOCX':
            binary_data = generate_docx_report(assessment, report_type)
        elif file_format == 'XLSX':
            binary_data = generate_xlsx_report(assessment, report_type)
        else:
            raise ValueError(f"Unsupported format: {file_format}")

        # Save binary file in storage
        filename = f"{report_type}_v{version.version_number}.{file_format.lower()}"
        version.file.save(filename, ContentFile(binary_data), save=False)
        version.status = 'Pending' # Generated, now pending security check
        version.save()

        # Trigger ClamAV scan task for the report
        scan_report_clamav.delay(version.id)
        return f"Report {report_type} ({file_format}) successfully generated for version {version.id}."

    except Exception as e:
        err_msg = traceback.format_exc()
        logger.error(f"Failed to generate report version {report_version_id}: {e}\n{err_msg}")
        version.status = 'Failed'
        version.error_message = f"Generation Error: {e}\n{err_msg[:500]}"
        version.save()
        return f"Generation failed for version {version.id}: {e}"


@shared_task
def scan_report_clamav(report_version_id):
    """
    Celery task to verify generated reports do not contain malware before they are served.
    """
    try:
        version = ReportVersion.objects.get(id=report_version_id)
    except ReportVersion.DoesNotExist:
        logger.error(f"ReportVersion {report_version_id} not found for scanning.")
        return f"ReportVersion {report_version_id} not found."

    if not version.file:
        version.status = 'Failed'
        version.error_message = "Scan Error: File payload not found."
        version.save()
        return "Scan error: No file payload."

    try:
        with version.file.open('rb') as f:
            status, results = scan_file_stream(f)

        version.status = status
        if status != 'Clean':
            version.error_message = f"Malware Scan Alert: {results}"
        version.save()

        # Log security audit event
        tenant = version.document.tenant
        user = version.generated_by

        AuditEvent.objects.create(
            tenant=tenant,
            user=user,
            event_type='FILE_SCAN',
            action='SCAN_COMPLETE' if status == 'Clean' else 'MALWARE_ALERT',
            ip_address='127.0.0.1',
            payload={
                'report_document_id': version.document.id,
                'report_version_id': version.id,
                'file_name': version.file.name,
                'status': status,
                'results': results,
                'origin': 'REPORT_GENERATION'
            }
        )

        return f"Scan complete for report version {version.id}: {status}"
    except Exception as e:
        logger.error(f"Error scanning generated report version {report_version_id}: {e}")
        version.status = 'Failed'
        version.error_message = f"Security Scan Error: {e}"
        version.save()
        return f"Scanning failed: {e}"
