import hashlib
import json
from django.db import models
from django.core.exceptions import ValidationError

class AuditEvent(models.Model):
    """
    Immutable, Write-Once-Read-Many (WORM) security audit ledger with signature chaining.
    """
    tenant = models.ForeignKey('tenants.Tenant', on_delete=models.CASCADE)
    user = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    event_type = models.CharField(max_length=100)
    action = models.CharField(max_length=50) # CREATE, UPDATE, DELETE, LOGIN, EXPORT
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    
    payload = models.JSONField(default=dict, help_text="State mapping diff details.")
    signature = models.CharField(max_length=64, blank=True, help_text="TAMPER SIGNATURE CHAIN HASH")

    class Meta:
        verbose_name = "Audit Event"
        verbose_name_plural = "Audit Events"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['tenant', 'event_type']),
            models.Index(fields=['tenant', 'timestamp']),
        ]

    def save(self, *args, **kwargs):
        # Enforce WORM: block updates to existing events
        if self.pk is not None:
            raise ValidationError("Audit log records are immutable and cannot be updated.")
            
        # Calculate signature chain hash
        # signature = SHA-256(prev_signature + event_type + action + payload_json)
        last_entry = AuditEvent.objects.order_by('-id').first()
        prev_sig = last_entry.signature if last_entry else ""
        
        payload_str = json.dumps(self.payload, sort_keys=True)
        message = f"{prev_sig}:{self.event_type}:{self.action}:{payload_str}"
        self.signature = hashlib.sha256(message.encode('utf-8')).hexdigest()
        
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # Enforce WORM: block deletions of audit events
        raise ValidationError("Audit log records are immutable and cannot be deleted.")
