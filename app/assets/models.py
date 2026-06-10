from django.db import models
from tenants.models import TenantOwnedSoftDeleteModel

class Asset(TenantOwnedSoftDeleteModel):
    """
    Asset model representing an information or physical asset within the organization.
    Isolates records at the Tenant and Client levels, inheriting soft-delete functionality.
    """
    TYPE_CHOICES = [
        ('Hardware', 'Hardware'),
        ('Software', 'Software'),
        ('Data', 'Information/Data'),
        ('Service', 'Service'),
        ('People', 'People'),
        ('Physical', 'Physical Infrastructure'),
    ]

    CLASSIFICATION_CHOICES = [
        ('Public', 'Public'),
        ('Internal', 'Internal'),
        ('Confidential', 'Confidential'),
        ('Restricted', 'Restricted'),
        ('Secret', 'Secret'),
    ]

    CRITICALITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]

    client = models.ForeignKey('tenants.Client', on_delete=models.CASCADE, related_name='assets')
    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=50, choices=TYPE_CHOICES, default='Hardware')
    supplier = models.CharField(max_length=255, blank=True)
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_assets')
    classification = models.CharField(max_length=50, choices=CLASSIFICATION_CHOICES, default='Internal')
    location = models.CharField(max_length=255, blank=True)
    criticality = models.CharField(max_length=50, choices=CRITICALITY_CHOICES, default='Medium')
    business_function = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)

    # Linkages
    central_risks = models.ManyToManyField('assessments.CentralRisk', blank=True, related_name='linked_assets')
    assessment_risks = models.ManyToManyField('assessments.RiskItem', blank=True, related_name='linked_assets')
    assessments = models.ManyToManyField('assessments.Assessment', blank=True, related_name='linked_assets')
    evidence_documents = models.ManyToManyField('evidence.EvidenceDocument', blank=True, related_name='linked_assets')

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'client']),
            models.Index(fields=['tenant', 'name']),
        ]

    def __str__(self):
        return f"{self.name} ({self.asset_type}) - Client: {self.client.name}"
