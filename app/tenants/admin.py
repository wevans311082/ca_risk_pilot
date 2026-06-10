from django.contrib import admin
from .models import Tenant, UserTenantMembership, Client

@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ('name', 'domain', 'status', 'is_deleted', 'created_at')
    list_filter = ('status', 'is_deleted')
    search_fields = ('name', 'domain')
    ordering = ('name',)

@admin.register(UserTenantMembership)
class UserTenantMembershipAdmin(admin.ModelAdmin):
    list_display = ('user', 'tenant', 'role', 'created_at')
    list_filter = ('role', 'tenant')
    search_fields = ('user__email', 'user__username', 'tenant__name')

@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'email', 'phone', 'is_deleted', 'created_at')
    list_filter = ('tenant', 'is_deleted')
    search_fields = ('name', 'email')
    ordering = ('name',)
