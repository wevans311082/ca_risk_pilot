from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """
    Custom User model for RiskPilot.
    Uses email as the primary identifier for SSO and local login.
    """
    email = models.EmailField(unique=True)
    last_session_key = models.CharField(max_length=40, null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def get_membership(self, tenant):
        """
        Retrieve membership record for the given tenant.
        """
        return self.memberships.filter(tenant=tenant).first()

    def is_tenant_admin(self, tenant):
        """
        Verify if user is an admin or owner of the given tenant.
        """
        membership = self.get_membership(tenant)
        return membership is not None and membership.role in ['owner', 'admin']


class UserProfile(models.Model):
    """
    Account profile extension holding contact details and corporate mappings.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=50, blank=True)
    title = models.CharField(max_length=100, blank=True)
    department = models.CharField(max_length=100, blank=True)

    # Multi-Factor Authentication fields
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.user.email}"
