from django.db import models
from tenants.models import TenantOwnedSoftDeleteModel

class Finding(TenantOwnedSoftDeleteModel):
    """
    An identified security vulnerability or compliance gap resulting from a Risk Item.
    """
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('InProgress', 'In Progress'),
        ('Resolved', 'Resolved'),
        ('FalsePositive', 'False Positive'),
    ]

    SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]

    assessment = models.ForeignKey('assessments.Assessment', on_delete=models.CASCADE, related_name='findings')
    risk_item = models.ForeignKey('assessments.RiskItem', on_delete=models.CASCADE, related_name='findings', null=True, blank=True)
    
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=50, choices=SEVERITY_CHOICES, default='Medium')
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Open')
    
    evidence = models.ManyToManyField('evidence.EvidenceDocument', related_name='findings', blank=True)
    
    assignee = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, related_name='assigned_findings')
    due_date = models.DateField(blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'assessment', 'status']),
            models.Index(fields=['tenant', 'risk_item']),
        ]

    def __str__(self):
        return f"{self.title} ({self.status})"


class Recommendation(TenantOwnedSoftDeleteModel):
    """
    Proposed remediation recommendation bound to a Finding.
    """
    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]

    EFFORT_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='recommendations')
    text = models.TextField()
    priority = models.CharField(max_length=50, choices=PRIORITY_CHOICES, default='Medium')
    effort = models.CharField(max_length=50, choices=EFFORT_CHOICES, default='Medium')
    cost_estimate = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True, help_text="Estimated cost in GBP (£).")

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'finding', 'priority']),
        ]

    def __str__(self):
        return f"Rec (Priority: {self.priority}) for Finding {self.finding.id}"
