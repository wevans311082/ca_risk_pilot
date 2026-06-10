from django.db import models
from tenants.models import TenantOwnedSoftDeleteModel

class Control(TenantOwnedSoftDeleteModel):
    """
    Control model representing administrative, technical, or physical security controls.
    Tracks effectiveness rating, maturity level, testing schedules, and linked system entities.
    """
    CONTROL_TYPE_CHOICES = [
        ('Administrative', 'Administrative'),
        ('Technical', 'Technical'),
        ('Physical', 'Physical'),
    ]

    EFFECTIVENESS_CHOICES = [
        ('Satisfactory', 'Satisfactory'),
        ('NeedsImprovement', 'Needs Improvement'),
        ('Ineffective', 'Ineffective'),
        ('NotTested', 'Not Tested'),
    ]

    MATURITY_CHOICES = [
        ('Initial', 'Initial/Ad-hoc'),
        ('Repeatable', 'Repeatable'),
        ('Defined', 'Defined'),
        ('Managed', 'Managed'),
        ('Optimizing', 'Optimizing'),
    ]

    client = models.ForeignKey('tenants.Client', on_delete=models.CASCADE, related_name='controls')
    name = models.CharField(max_length=255)
    control_type = models.CharField(max_length=50, choices=CONTROL_TYPE_CHOICES, default='Administrative')
    description = models.TextField(blank=True)
    effectiveness = models.CharField(max_length=50, choices=EFFECTIVENESS_CHOICES, default='NotTested')
    maturity = models.CharField(max_length=50, choices=MATURITY_CHOICES, default='Initial')
    last_tested_at = models.DateField(null=True, blank=True)
    next_test_date = models.DateField(null=True, blank=True)

    # Linkages
    central_risks = models.ManyToManyField('assessments.CentralRisk', blank=True, related_name='linked_controls')
    assessment_risks = models.ManyToManyField('assessments.RiskItem', blank=True, related_name='linked_controls')
    assessments = models.ManyToManyField('assessments.Assessment', blank=True, related_name='linked_controls')
    findings = models.ManyToManyField('findings.Finding', blank=True, related_name='linked_controls')
    recommendations = models.ManyToManyField('findings.Recommendation', blank=True, related_name='linked_controls')

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'client']),
            models.Index(fields=['tenant', 'name']),
        ]

    def __str__(self):
        return f"{self.name} ({self.control_type}) - Status: {self.get_effectiveness_display()}"
