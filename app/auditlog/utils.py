from .models import AuditEvent

def log_audit_event(tenant, user, event_type, action, payload, ip_address=None):
    """
    Central utility to log an immutable audit event to the ledger.
    """
    try:
        # Enforce that user is authenticated, else log as None (anonymous/system)
        auth_user = user if user and user.is_authenticated else None
        return AuditEvent.objects.create(
            tenant=tenant,
            user=auth_user,
            event_type=event_type,
            action=action,
            payload=payload or {},
            ip_address=ip_address
        )
    except Exception as e:
        import logging
        logging.getLogger("auditlog").error(f"Failed to write audit event: {e}", exc_info=True)
        return None
