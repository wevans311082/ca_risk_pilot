from contextvars import ContextVar

# Thread-safe and async-safe active tenant storage
_active_tenant = ContextVar('active_tenant', default=None)

def set_current_tenant(tenant):
    """
    Set the tenant in the current context.
    """
    return _active_tenant.set(tenant)

def get_current_tenant():
    """
    Retrieve the tenant in the current context.
    """
    return _active_tenant.get()

def clear_current_tenant():
    """
    Clear the tenant from the current context.
    """
    _active_tenant.set(None)
