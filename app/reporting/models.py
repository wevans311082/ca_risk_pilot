from django.db import models
from tenants.models import TenantOwnedSoftDeleteModel

def tenant_report_path(instance, filename):
    """
    Storage path partitioned by tenant.
    """
    return f"tenant_{instance.document.tenant.id}/reports/{filename}"

class ReportDocument(TenantOwnedSoftDeleteModel):
    """
    Logical report entity for a specific assessment, format, and report type.
    """
    REPORT_TYPE_CHOICES = [
        ('ExecutiveSummary', 'Executive Summary'),
        ('DetailedRiskAssessment', 'Detailed Risk Assessment'),
        ('RiskRegister', 'Risk Register'),
        ('TreatmentPlan', 'Treatment Plan'),
        ('ChangeRequest', 'Change Request'),
    ]

    FILE_FORMAT_CHOICES = [
        ('PDF', 'PDF'),
        ('DOCX', 'Word (DOCX)'),
        ('XLSX', 'Excel (XLSX)'),
    ]

    assessment = models.ForeignKey('assessments.Assessment', on_delete=models.CASCADE, related_name='report_documents')
    report_type = models.CharField(max_length=50, choices=REPORT_TYPE_CHOICES)
    file_format = models.CharField(max_length=10, choices=FILE_FORMAT_CHOICES)
    created_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, related_name='created_reports')

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'assessment', 'report_type', 'file_format']),
        ]

    def __str__(self):
        return f"{self.get_report_type_display()} ({self.file_format}) for {self.assessment.name}"


class ReportVersion(models.Model):
    """
    An actual generated file version for a logical ReportDocument.
    """
    STATUS_CHOICES = [
        ('Pending', 'Pending Scan/Generation'),
        ('Clean', 'Clean'),
        ('Infected', 'Infected'),
        ('Failed', 'Failed Generation'),
    ]

    document = models.ForeignKey(ReportDocument, on_delete=models.CASCADE, related_name='versions')
    version_number = models.PositiveIntegerField(default=1)
    
    file = models.FileField(upload_to=tenant_report_path, null=True, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pending')
    error_message = models.TextField(blank=True)
    
    generated_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, related_name='generated_reports')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-version_number']
        indexes = [
            models.Index(fields=['document', 'version_number']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.document.report_type} v{self.version_number} ({self.status})"


class ReportDownloadHistory(models.Model):
    """
    Audit log record of whenever a user downloads a report version.
    """
    version = models.ForeignKey(ReportVersion, on_delete=models.CASCADE, related_name='downloads')
    downloaded_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, related_name='downloaded_reports')
    downloaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-downloaded_at']
        indexes = [
            models.Index(fields=['version', 'downloaded_at']),
        ]

    def __str__(self):
        downloader = self.downloaded_by.email if self.downloaded_by else "Anonymous"
        return f"{downloader} downloaded {self.version} at {self.downloaded_at}"
