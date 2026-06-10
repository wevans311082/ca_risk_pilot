import time
from django.test import TestCase, Client as HttpClient
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.contrib.sessions.models import Session
from unittest.mock import patch

from accounts.models import User, UserProfile
from tenants.models import Tenant, UserTenantMembership
from auditlog.models import AuditEvent
from auditlog.signing import generate_signed_url, verify_signed_url
from accounts.mfa import generate_mfa_secret, verify_totp, get_hotp_token

class RiskPilotSecurityTests(TestCase):
    def setUp(self):
        # Create a test tenant
        self.tenant = Tenant.objects.create(name="Secure Corp", domain="securecorp")
        
        # Create test users
        self.user = User.objects.create_user(
            username="user@securecorp.com",
            email="user@securecorp.com",
            password="Password123!"
        )
        self.admin = User.objects.create_user(
            username="admin@securecorp.com",
            email="admin@securecorp.com",
            password="Password123!"
        )
        
        # Setup memberships
        UserTenantMembership.objects.create(user=self.user, tenant=self.tenant, role="assessor")
        UserTenantMembership.objects.create(user=self.admin, tenant=self.tenant, role="admin")
        
        # Ensure profiles exist
        self.user_profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.admin_profile, _ = UserProfile.objects.get_or_create(user=self.admin)

    def test_audit_event_immutability(self):
        """
        WORM Check: Verify that AuditEvent objects are immutable and cannot be updated or deleted.
        """
        event = AuditEvent.objects.create(
            tenant=self.tenant,
            user=self.user,
            event_type="SECURITY",
            action="TEST_ACTION",
            payload={"test": "data"}
        )
        
        # Verify it has a tamper signature
        self.assertTrue(event.signature)
        
        # Try to update/save again -> should raise ValidationError
        event.action = "TAMPERED"
        with self.assertRaises(ValidationError):
            event.save()
            
        # Try to delete -> should raise ValidationError
        with self.assertRaises(ValidationError):
            event.delete()

    def test_session_concurrency(self):
        """
        Enforce Session Concurrency: Verify that logging in from a second device/window
        invalidates the first session.
        """
        # Device/Browser 1
        client1 = HttpClient(HTTP_HOST="securecorp.localhost")
        res1 = client1.post(reverse("login"), {
            "username": self.user.email,
            "password": "Password123!"
        })
        self.assertEqual(res1.status_code, 302)
        
        # Grab first session key
        session_key1 = client1.session.session_key
        self.user.refresh_from_db()
        self.assertEqual(self.user.last_session_key, session_key1)
        
        # Make a request with Client 1 -> Should work (200 OK)
        res_test1 = client1.get(reverse("dashboard"))
        self.assertEqual(res_test1.status_code, 200)

        # Device/Browser 2 (User logs in from another client)
        client2 = HttpClient(HTTP_HOST="securecorp.localhost")
        res2 = client2.post(reverse("login"), {
            "username": self.user.email,
            "password": "Password123!"
        })
        self.assertEqual(res2.status_code, 302)
        
        # Session key should be updated on the user model
        session_key2 = client2.session.session_key
        self.user.refresh_from_db()
        self.assertEqual(self.user.last_session_key, session_key2)
        self.assertNotEqual(session_key1, session_key2)

        # Try to make a request with Client 1 again -> Middleware should terminate session and redirect
        res_test2 = client1.get(reverse("dashboard"))
        self.assertEqual(res_test2.status_code, 302)
        self.assertIn(reverse("login"), res_test2.url)

    def test_signed_url_validation_and_tampering(self):
        """
        Signed URLs Check: Verify URL generation, validation, and rejection of tampered parameters.
        """
        # Generate a signed URL for a file download (v1)
        url = generate_signed_url("download_file", args=[1])
        self.assertIn("sig=", url)
        
        # Extract path and signature
        path, query = url.split("?")
        sig = query.split("sig=")[1]
        
        # 1. Valid Signature
        self.assertTrue(verify_signed_url(path, sig))
        
        # 2. Tampered Path (e.g. changing ID to 2)
        tampered_path = path.replace("/1/", "/2/")
        self.assertFalse(verify_signed_url(tampered_path, sig))
        
        # 3. Tampered Signature
        self.assertFalse(verify_signed_url(path, sig + "tamper"))
        
        # 4. Expired Signature (Simulate max_age = 0)
        self.assertFalse(verify_signed_url(path, sig, max_age=0))

    def test_totp_mfa_helpers(self):
        """
        TOTP MFA algorithm: Verify secret generation and verify_totp helper functions.
        """
        secret = generate_mfa_secret()
        self.assertEqual(len(secret), 16) # 10 bytes base32 encoded -> 16 chars
        
        # Get current time interval code
        current_time = int(time.time()) // 30
        valid_code = get_hotp_token(secret, current_time)
        
        # Verify valid code passes
        self.assertTrue(verify_totp(secret, valid_code))
        
        # Verify window works (e.g. previous token)
        prev_code = get_hotp_token(secret, current_time - 1)
        self.assertTrue(verify_totp(secret, prev_code))
        
        # Verify invalid code fails
        self.assertFalse(verify_totp(secret, "000000"))
        self.assertFalse(verify_totp(secret, "abcdef"))

    def test_mfa_login_flow(self):
        """
        MFA workflow: Verify login prompts MFA verify view, and correct code logs in.
        """
        # Enable MFA for standard user
        secret = generate_mfa_secret()
        self.user_profile.mfa_enabled = True
        self.user_profile.mfa_secret = secret
        self.user_profile.save()
        
        client = HttpClient(HTTP_HOST="securecorp.localhost")
        
        # 1. Post valid credentials -> Should redirect to MFA verification, not dashboard
        res = client.post(reverse("login"), {
            "username": self.user.email,
            "password": "Password123!"
        })
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.url, reverse("mfa_verify"))
        
        # User is not logged in yet
        self.assertNotIn("_auth_user_id", client.session)
        
        # Check that MFA_PENDING audit event was logged
        audit_pending = AuditEvent.objects.filter(
            tenant=self.tenant,
            user=self.user,
            event_type="AUTHENTICATION",
            action="MFA_PENDING"
        ).exists()
        self.assertTrue(audit_pending)

        # 2. Submit wrong code -> should fail and remain unauthenticated
        res_fail = client.post(reverse("mfa_verify"), {"code": "000000"})
        self.assertEqual(res_fail.status_code, 200) # Re-renders with error
        self.assertNotIn("_auth_user_id", client.session)
        
        # Check that MFA_VERIFIED_FAILED audit event was logged
        audit_failed = AuditEvent.objects.filter(
            tenant=self.tenant,
            user=self.user,
            event_type="AUTHENTICATION",
            action="MFA_VERIFIED_FAILED"
        ).exists()
        self.assertTrue(audit_failed)

        # 3. Submit correct code -> should authenticate and redirect to dashboard
        current_time = int(time.time()) // 30
        correct_code = get_hotp_token(secret, current_time)
        res_success = client.post(reverse("mfa_verify"), {"code": correct_code})
        self.assertEqual(res_success.status_code, 302)
        self.assertEqual(res_success.url, reverse("dashboard"))
        
        # User is authenticated
        self.assertEqual(int(client.session["_auth_user_id"]), self.user.id)
        
        # Check MFA_VERIFIED and LOGIN audit logs
        self.assertTrue(AuditEvent.objects.filter(
            tenant=self.tenant, user=self.user, event_type="AUTHENTICATION", action="MFA_VERIFIED"
        ).exists())
        self.assertTrue(AuditEvent.objects.filter(
            tenant=self.tenant, user=self.user, event_type="AUTHENTICATION", action="LOGIN"
        ).exists())

    def test_failed_login_auditing(self):
        """
        Verify that failed login attempts are logged as anonymous events.
        """
        client = HttpClient(HTTP_HOST="securecorp.localhost")
        res = client.post(reverse("login"), {
            "username": "nonexistent@securecorp.com",
            "password": "WrongPassword"
        })
        self.assertEqual(res.status_code, 200) # Show errors
        
        # Check audit event for LOGIN_FAILED
        failed_event = AuditEvent.objects.filter(
            tenant=self.tenant,
            user=None,
            event_type="AUTHENTICATION",
            action="LOGIN_FAILED",
            payload__email="nonexistent@securecorp.com"
        ).exists()
        self.assertTrue(failed_event)

    def test_mfa_setup_auditing(self):
        """
        Verify that enabling/disabling MFA in the settings logs audit events.
        """
        client = HttpClient(HTTP_HOST="securecorp.localhost")
        client.login(email=self.user.email, password="Password123!")
        
        # Post to enable MFA
        temp_secret = generate_mfa_secret()
        current_time = int(time.time()) // 30
        code = get_hotp_token(temp_secret, current_time)
        
        res_enable = client.post(reverse("mfa_setup"), {
            "action": "enable",
            "secret": temp_secret,
            "code": code
        })
        self.assertEqual(res_enable.status_code, 302)
        
        # Check DB
        self.user_profile.refresh_from_db()
        self.assertTrue(self.user_profile.mfa_enabled)
        self.assertEqual(self.user_profile.mfa_secret, temp_secret)
        
        # Check audit log
        self.assertTrue(AuditEvent.objects.filter(
            tenant=self.tenant,
            user=self.user,
            event_type="AUTHENTICATION",
            action="MFA_ENABLED"
        ).exists())
        
        # Post to disable MFA
        res_disable = client.post(reverse("mfa_setup"), {
            "action": "disable"
        })
        self.assertEqual(res_disable.status_code, 302)
        
        # Check DB
        self.user_profile.refresh_from_db()
        self.assertFalse(self.user_profile.mfa_enabled)
        
        # Check audit log
        self.assertTrue(AuditEvent.objects.filter(
            tenant=self.tenant,
            user=self.user,
            event_type="AUTHENTICATION",
            action="MFA_DISABLED"
        ).exists())
