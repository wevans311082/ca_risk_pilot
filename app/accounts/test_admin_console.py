from django.test import Client as HttpClient, TestCase
from django.urls import reverse

from accounts.models import User, UserProfile
from tenants.models import Client, Tenant, UserTenantMembership


class AdminConsoleTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(name="Secure Corp", domain="securecorp")
        self.client_org = Client.objects.create(tenant=self.tenant, name="Client A")
        self.admin = User.objects.create_user(
            username="admin@securecorp.com",
            email="admin@securecorp.com",
            password="Password123!",
        )
        self.assessor = User.objects.create_user(
            username="assessor@securecorp.com",
            email="assessor@securecorp.com",
            password="Password123!",
        )
        UserTenantMembership.objects.create(user=self.admin, tenant=self.tenant, role="admin")
        UserTenantMembership.objects.create(user=self.assessor, tenant=self.tenant, role="assessor")

    def client_for(self, user):
        client = HttpClient(HTTP_HOST="securecorp.localhost")
        client.force_login(user)
        return client

    def test_admin_console_allows_tenant_admin(self):
        response = self.client_for(self.admin).get(reverse("admin_dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Admin Console")

    def test_admin_console_blocks_non_admin(self):
        response = self.client_for(self.assessor).get(reverse("admin_dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("dashboard"))

    def test_tenant_admin_can_create_user_and_reset_mfa(self):
        client = self.client_for(self.admin)
        response = client.post(
            reverse("admin_user_create"),
            {
                "email": "new.user@securecorp.com",
                "first_name": "New",
                "last_name": "User",
                "role": "client",
                "client": self.client_org.pk,
                "password": "Password123!",
                "is_active": "on",
            },
        )
        self.assertEqual(response.status_code, 302)

        user = User.objects.get(email="new.user@securecorp.com")
        membership = UserTenantMembership.objects.get(user=user, tenant=self.tenant)
        self.assertEqual(membership.role, "client")
        self.assertEqual(membership.client, self.client_org)

        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.mfa_enabled = True
        profile.mfa_secret = "ABC123"
        profile.save()

        response = client.post(reverse("admin_user_reset_mfa", args=[user.pk]))
        self.assertEqual(response.status_code, 302)
        profile.refresh_from_db()
        self.assertFalse(profile.mfa_enabled)
        self.assertEqual(profile.mfa_secret, "")

    def test_sso_settings_preserve_existing_secret_when_blank(self):
        self.tenant.m365_client_secret = "existing-secret"
        self.tenant.save()
        response = self.client_for(self.admin).post(
            reverse("admin_sso_settings"),
            {
                "microsoft_tenant_id": "11111111-1111-1111-1111-111111111111",
                "m365_sso_enabled": "on",
                "m365_client_id": "client-id",
                "m365_client_secret": "",
                "m365_auto_create_users": "on",
                "m365_default_role": "viewer",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.tenant.refresh_from_db()
        self.assertTrue(self.tenant.m365_sso_enabled)
        self.assertEqual(self.tenant.m365_client_secret, "existing-secret")

    def test_m365_start_redirects_to_microsoft_when_configured(self):
        self.tenant.microsoft_tenant_id = "11111111-1111-1111-1111-111111111111"
        self.tenant.m365_sso_enabled = True
        self.tenant.m365_client_id = "client-id"
        self.tenant.m365_client_secret = "client-secret"
        self.tenant.save()

        response = HttpClient(HTTP_HOST="securecorp.localhost").get(reverse("m365_sso_start"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login.microsoftonline.com", response.url)
        self.assertIn("client_id=client-id", response.url)
