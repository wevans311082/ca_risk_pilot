from django.contrib import admin
from .models import AuditEvent

@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'tenant', 'user', 'event_type', 'action', 'ip_address')
    list_filter = ('tenant', 'event_type', 'action')
    search_fields = ('user__email', 'user__username', 'event_type', 'action')
    ordering = ('-timestamp',)

    # Restrict operations at the admin panel interface level for WORM compliance
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    # Prevent editing of existing fields
    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields]
