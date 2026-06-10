from django.db import models
from django.utils import timezone
from .isolation import get_current_tenant

class Tenant(models.Model):
    """
    SaaS Tenant representing a customer organization.
    """
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('suspended', 'Suspended'),
        ('inactive', 'Inactive'),
    ]

    MAIL_SERVICE_CHOICES = [
        ('GLOBAL', 'Global System Mailer'),
        ('TENANT_SMTP', 'Tenant SMTP Mailer'),
        ('TENANT_M365_GRAPH', 'Tenant M365 Graph API'),
    ]

    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='active')
    
    # Microsoft 365 Entra ID tenant validation mapping
    microsoft_tenant_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    
    # Outbound email isolation settings
    mail_service_type = models.CharField(max_length=50, choices=MAIL_SERVICE_CHOICES, default='GLOBAL')
    mail_credentials = models.TextField(blank=True, null=True, help_text="AES-256 encrypted SMTP details or OAuth credentials.")
    mail_from_address = models.EmailField(blank=True, null=True)

    # Soft-delete flags for Tenant itself
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def delete(self, using=None, keep_parents=False):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=['is_deleted', 'deleted_at'])

    def __str__(self):
        return self.name


class UserTenantMembership(models.Model):
    """
    Maps users to tenants with specific roles for logical RBAC isolation.
    """
    ROLE_CHOICES = [
        ('owner', 'Owner'),
        ('admin', 'Administrator'),
        ('assessor', 'Assessor'),
        ('reviewer', 'Reviewer'),
        ('client', 'Client'),
        ('viewer', 'Viewer'),
    ]

    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE, related_name='memberships')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='viewer')
    client = models.ForeignKey('tenants.Client', on_delete=models.SET_NULL, null=True, blank=True, related_name='memberships')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'tenant')

    def __str__(self):
        return f"{self.user.email} -> {self.tenant.name} ({self.role})"


# Soft Delete & Tenant Isolation ORM Utilities
class TenantSoftDeleteQuerySet(models.QuerySet):
    """
    Combines tenant isolation filtering and soft-delete updates on QuerySets.
    """
    def filter_by_tenant(self):
        active_tenant = get_current_tenant()
        if active_tenant:
            return self.filter(tenant=active_tenant)
        return self

    def active(self):
        return self.filter(is_deleted=False)

    def delete(self):
        # Perform soft-delete updates instead of SQL hard deletes
        return self.update(is_deleted=True, deleted_at=timezone.now())


class TenantSoftDeleteManager(models.Manager):
    """
    Default manager that filters out soft-deleted records and isolates by tenant.
    """
    def get_queryset(self):
        return TenantSoftDeleteQuerySet(self.model, using=self._db).filter_by_tenant().active()

    def all_with_deleted(self):
        """
        Returns all records for the active tenant, including soft-deleted ones.
        """
        return TenantSoftDeleteQuerySet(self.model, using=self._db).filter_by_tenant()


class TenantOwnedSoftDeleteModel(models.Model):
    """
    Abstract base model that enforces row-level tenant association and soft-deletes.
    """
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Manager registrations
    objects = TenantSoftDeleteManager()
    unfiltered = models.Manager()

    class Meta:
        abstract = True

    def delete(self, using=None, keep_parents=False):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save(update_fields=['is_deleted', 'deleted_at'])

    def save(self, *args, **kwargs):
        # Automatically assign active context tenant if not specified
        if not self.tenant_id:
            active_tenant = get_current_tenant()
            if active_tenant:
                self.tenant = active_tenant
        super().save(*args, **kwargs)


class TenantOwnedModel(models.Model):
    """
    Abstract base model that enforces row-level tenant association (without soft-delete).
    """
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)

    # Custom managers
    class SimpleTenantQuerySet(models.QuerySet):
        def filter_by_tenant(self):
            active_tenant = get_current_tenant()
            if active_tenant:
                return self.filter(tenant=active_tenant)
            return self

    class SimpleTenantManager(models.Manager):
        def get_queryset(self):
            return TenantOwnedModel.SimpleTenantQuerySet(self.model, using=self._db).filter_by_tenant()

    objects = SimpleTenantManager()
    unfiltered = models.Manager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self.tenant_id:
            active_tenant = get_current_tenant()
            if active_tenant:
                self.tenant = active_tenant
        super().save(*args, **kwargs)


class Client(TenantOwnedSoftDeleteModel):
    """
    A Client assessed by a Tenant. Bounded to a single Tenant.
    """
    name = models.CharField(max_length=255)
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=50, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'name']),
        ]

    def __str__(self):
        return self.name
