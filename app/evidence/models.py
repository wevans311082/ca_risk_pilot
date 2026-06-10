from django.db import models
from tenants.models import TenantOwnedSoftDeleteModel

def tenant_upload_path(instance, filename):
    """
    Quarantine storage path partitioned by tenant.
    """
    return f"tenant_{instance.document.tenant.id}/pending/{filename}"

class EvidenceDocument(TenantOwnedSoftDeleteModel):
    """
    Container representing a logical evidence document.
    Can be associated with an Assessment, RiskItem, Finding, or RiskTreatment.
    """
    assessment = models.ForeignKey('assessments.Assessment', on_delete=models.CASCADE, related_name='evidence_documents', null=True, blank=True)
    risk_item = models.ForeignKey('assessments.RiskItem', on_delete=models.CASCADE, related_name='evidence_documents', null=True, blank=True)
    finding = models.ForeignKey('findings.Finding', on_delete=models.CASCADE, related_name='evidence_documents', null=True, blank=True)
    treatment = models.ForeignKey('assessments.RiskTreatment', on_delete=models.CASCADE, related_name='evidence_documents', null=True, blank=True)
    
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, related_name='created_documents')

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'name']),
        ]

    def __str__(self):
        return self.name


class EvidenceVersion(models.Model):
    """
    A specific uploaded file version of an EvidenceDocument.
    """
    STATUS_CHOICES = [
        ('Pending', 'Pending Scan'),
        ('Clean', 'Clean'),
        ('Infected', 'Infected'),
    ]

    document = models.ForeignKey(EvidenceDocument, on_delete=models.CASCADE, related_name='versions')
    version_number = models.PositiveIntegerField(default=1)
    
    file = models.FileField(upload_to=tenant_upload_path)
    file_name = models.CharField(max_length=255)
    content_type = models.CharField(max_length=100)
    file_size = models.PositiveIntegerField(help_text="File size in bytes.")
    sha256_hash = models.CharField(max_length=64, blank=True, help_text="SHA-256 hash checksum.")
    
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pending')
    scan_results = models.TextField(blank=True, help_text="ClamAV scan results or errors.")
    extracted_text = models.TextField(blank=True, help_text="Plain text extracted from PDF/Word/Excel.")
    
    uploaded_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, related_name='uploaded_versions')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-version_number']
        indexes = [
            models.Index(fields=['document', 'version_number']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.file_name} v{self.version_number} ({self.status})"
