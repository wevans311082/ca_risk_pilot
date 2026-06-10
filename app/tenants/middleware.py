from django.utils.deprecation import MiddlewareMixin
from .isolation import set_current_tenant, clear_current_tenant

class TenantMiddleware(MiddlewareMixin):
    """
    Middleware to resolve the active tenant from the request domain
    or user session and bind it to the context.
    """
    def process_request(self, request):
        from .models import Tenant
        
        host = request.get_host().split(':')[0]
        parts = host.split('.')
        
        tenant = None
        # Subdomain resolution (e.g., client.riskpilot.com -> client)
        if len(parts) > 1 and parts[0] not in ['www', 'localhost', '127', 'web']:
            subdomain = parts[0]
            try:
                tenant = Tenant.objects.get(domain=subdomain)
            except Tenant.DoesNotExist:
                pass
        
        # Fallback to the user's default/first registered tenant if logged in
        if not tenant and request.user.is_authenticated:
            # Note: We assume the related name in UserTenantMembership is 'memberships'
            membership = getattr(request.user, 'memberships', None)
            if membership:
                first_membership = membership.first()
                if first_membership:
                    tenant = first_membership.tenant
        
        # Bind resolved tenant to request object and thread context
        request.tenant = tenant
        set_current_tenant(tenant)

        request.user_membership = None
        request.user_role = None
        request.user_client = None

        if request.user.is_authenticated:
            if request.user.is_superuser:
                request.user_role = 'admin'
            elif tenant:
                membership = request.user.memberships.filter(tenant=tenant).first()
                if membership:
                    request.user_membership = membership
                    request.user_role = membership.role
                    request.user_client = membership.client

    def process_response(self, request, response):
        # Clear context to prevent leaks across threads/requests
        clear_current_tenant()
        return response

    def process_exception(self, request, exception):
        # Ensure context is cleared even on error
        clear_current_tenant()
