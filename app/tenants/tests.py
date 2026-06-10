from django.test import TestCase
from django.core.exceptions import ValidationError
from django.utils import timezone
from accounts.models import User
from tenants.models import Tenant, Client, UserTenantMembership
from tenants.isolation import set_current_tenant, clear_current_tenant
# No assessments imports needed
from auditlog.models import AuditEvent

class TenantIsolationTestCase(TestCase):
    def setUp(self):
        # Create test users
        self.user = User.objects.create_user(username='tester', email='tester@riskpilot.local', password='password123')
        
        # Create two separate tenants
        self.tenant_a = Tenant.objects.create(name='Tenant Alpha', domain='alpha')
        self.tenant_b = Tenant.objects.create(name='Tenant Beta', domain='beta')
        
        # Link user to Tenant Alpha
        UserTenantMembership.objects.create(user=self.user, tenant=self.tenant_a, role='admin')

    def tearDown(self):
        clear_current_tenant()

    def test_tenant_context_isolation(self):
        """
        Verify that TenantOwnedSoftDeleteModel queries are isolated by active tenant context.
        """
        # Set context to Tenant Alpha
        set_current_tenant(self.tenant_a)
        client_a = Client.objects.create(name='Client Alpha 1', email='alpha1@client.local')
        
        # Set context to Tenant Beta
        set_current_tenant(self.tenant_b)
        client_b = Client.objects.create(name='Client Beta 1', email='beta1@client.local')
        
        # Assert Tenant Beta only sees client_b
        clients_beta = Client.objects.all()
        self.assertEqual(clients_beta.count(), 1)
        self.assertEqual(clients_beta.first().name, 'Client Beta 1')
        
        # Set context back to Tenant Alpha
        set_current_tenant(self.tenant_a)
        clients_alpha = Client.objects.all()
        self.assertEqual(clients_alpha.count(), 1)
        self.assertEqual(clients_alpha.first().name, 'Client Alpha 1')


class SoftDeleteTestCase(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(name='SoftDelete Tenant', domain='soft')
        set_current_tenant(self.tenant)

    def tearDown(self):
        clear_current_tenant()

    def test_soft_delete_lifecycle(self):
        """
        Verify that soft-deleted items are excluded from default objects manager but retrievable.
        """
        client = Client.objects.create(name='Temporary Client', email='temp@client.local')
        client_id = client.id
        
        # Assert is in list
        self.assertEqual(Client.objects.filter(id=client_id).count(), 1)
        
        # Perform soft delete
        client.delete()
        
        # Assert is hidden from default queryset
        self.assertEqual(Client.objects.filter(id=client_id).count(), 0)
        self.assertEqual(Client.objects.all().count(), 0)
        
        # Assert is visible in all_with_deleted manager
        all_clients = Client.objects.all_with_deleted()
        self.assertEqual(all_clients.count(), 1)
        
        deleted_client = all_clients.first()
        self.assertTrue(deleted_client.is_deleted)
        self.assertIsNotNone(deleted_client.deleted_at)


class AuditEventWORMTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='auditor', email='auditor@riskpilot.local', password='password123')
        self.tenant = Tenant.objects.create(name='Audit Tenant', domain='audit')

    def test_audit_event_immutability(self):
        """
        Verify that AuditEvent records cannot be updated or deleted (WORM compliance).
        """
        event = AuditEvent.objects.create(
            tenant=self.tenant,
            user=self.user,
            event_type='TEST_EVENT',
            action='CREATE',
            ip_address='127.0.0.1',
            payload={'field': 'value'}
        )
        
        # Verify signature was generated
        self.assertIsNotNone(event.signature)
        self.assertNotEqual(event.signature, "")
        
        # Attempt edit: should raise ValidationError
        with self.assertRaises(ValidationError):
            event.action = 'UPDATE'
            event.save()
            
        # Attempt delete: should raise ValidationError
        with self.assertRaises(ValidationError):
            event.delete()

    def test_signature_chaining(self):
        """
        Verify that each AuditEvent signature chain connects to the preceding event.
        """
        event1 = AuditEvent.objects.create(
            tenant=self.tenant,
            user=self.user,
            event_type='EVENT_1',
            action='CREATE',
            payload={'id': 1}
        )
        
        event2 = AuditEvent.objects.create(
            tenant=self.tenant,
            user=self.user,
            event_type='EVENT_2',
            action='UPDATE',
            payload={'id': 2}
        )
        
        # Check signatures are different
        self.assertNotEqual(event1.signature, event2.signature)
        
        # Manually calculate event2 signature and verify matches
        import hashlib
        import json
        payload_str = json.dumps(event2.payload, sort_keys=True)
        expected_msg = f"{event1.signature}:{event2.event_type}:{event2.action}:{payload_str}"
        expected_sig = hashlib.sha256(expected_msg.encode('utf-8')).hexdigest()
        
        self.assertEqual(event2.signature, expected_sig)
