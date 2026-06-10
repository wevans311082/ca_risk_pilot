from django.db import models
from django.contrib.auth import get_user_model
from tenants.models import TenantOwnedSoftDeleteModel, TenantOwnedModel
from assessments.models import Assessment, RiskItem, RiskTreatment, TemplateAssessment
from findings.models import Finding
from evidence.models import EvidenceDocument

User = get_user_model()

class Comment(TenantOwnedSoftDeleteModel):
    """
    Comment or message representing discussions on various risk assessor items.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='collaboration_comments')
    text = models.TextField()
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')

    # Association hooks
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, null=True, blank=True, related_name='comments')
    risk_item = models.ForeignKey(RiskItem, on_delete=models.CASCADE, null=True, blank=True, related_name='comments')
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, null=True, blank=True, related_name='comments')
    treatment = models.ForeignKey(RiskTreatment, on_delete=models.CASCADE, null=True, blank=True, related_name='comments')
    template_assessment = models.ForeignKey(TemplateAssessment, on_delete=models.CASCADE, null=True, blank=True, related_name='comments')

    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['tenant', 'assessment']),
            models.Index(fields=['tenant', 'risk_item']),
            models.Index(fields=['tenant', 'finding']),
            models.Index(fields=['tenant', 'treatment']),
            models.Index(fields=['tenant', 'template_assessment']),
        ]

    def __str__(self):
        return f"Comment by {self.user.email} on {self.created_at}"


class EvidenceRequest(TenantOwnedSoftDeleteModel):
    """
    A request dispatched by assessors/reviewers to clients for specific evidence.
    """
    STATUS_CHOICES = [
        ('Pending', 'Pending Client Submission'),
        ('Submitted', 'Submitted by Client'),
        ('Approved', 'Approved & Linked'),
        ('Rejected', 'Rejected (Needs Update)'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    client = models.ForeignKey('tenants.Client', on_delete=models.CASCADE, related_name='evidence_requests')
    
    # Target context links
    assessment = models.ForeignKey(Assessment, on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_requests')
    risk_item = models.ForeignKey(RiskItem, on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_requests')
    finding = models.ForeignKey(Finding, on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_requests')

    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Pending')
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='requested_evidences')
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_evidence_requests')
    
    # Response fields
    submitted_evidence = models.ForeignKey(EvidenceDocument, on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_requests')
    client_response = models.TextField(blank=True)
    rejection_notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'client', 'status']),
        ]

    def __str__(self):
        return f"Request: {self.title} ({self.status})"


class Notification(TenantOwnedModel):
    """
    Alert notification pushed to users for collaboration events (replies, mentions, evidence requests).
    """
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    message = models.TextField()
    url = models.CharField(max_length=255, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'recipient', 'is_read']),
        ]

    def __str__(self):
        return f"Alert for {self.recipient.email} - Read: {self.is_read}"


class CollaborationActivity(TenantOwnedModel):
    """
    Timeline audit log feed for collaboration actions.
    """
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action_type = models.CharField(max_length=100) # comment_created, request_created, status_updated
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'created_at']),
        ]

    def __str__(self):
        return f"{self.user.email if self.user else 'System'} - {self.action_type}"
