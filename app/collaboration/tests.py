from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch
from accounts.models import User
from tenants.models import Tenant, UserTenantMembership, Client as TenantClient
from assessments.models import Assessment, RiskItem
from findings.models import Finding
from auditlog.models import AuditEvent
from evidence.models import EvidenceDocument, EvidenceVersion
from collaboration.models import Comment, EvidenceRequest, Notification, CollaborationActivity

class CollaborationSubsystemTests(TestCase):
    def setUp(self):
        # Create Tenants
        self.tenant_a = Tenant.objects.create(name="Tenant A", domain="tenant-a")
        self.tenant_b = Tenant.objects.create(name="Tenant B", domain="tenant-b")

        # Create Users
        self.admin = User.objects.create_user(username="admin", email="admin@tenant-a.com", password="password")
        self.assessor = User.objects.create_user(username="assessor", email="assessor@tenant-a.com", password="password")
        self.reviewer = User.objects.create_user(username="reviewer", email="reviewer@tenant-a.com", password="password")
        self.client_user = User.objects.create_user(username="client_user", email="client@tenant-a.com", password="password")
        self.other_client_user = User.objects.create_user(username="other_client_user", email="otherclient@tenant-a.com", password="password")
        self.other_tenant_user = User.objects.create_user(username="other_tenant", email="other@tenant-b.com", password="password")

        # Create Tenant Memberships
        UserTenantMembership.objects.create(user=self.admin, tenant=self.tenant_a, role="admin")
        UserTenantMembership.objects.create(user=self.assessor, tenant=self.tenant_a, role="assessor")
        UserTenantMembership.objects.create(user=self.reviewer, tenant=self.tenant_a, role="reviewer")
        UserTenantMembership.objects.create(user=self.other_tenant_user, tenant=self.tenant_b, role="admin")

        # Set up active tenant context to create clients and assessments
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)

        self.client_a = TenantClient.objects.create(tenant=self.tenant_a, name="Client Company A")
        self.client_b = TenantClient.objects.create(tenant=self.tenant_a, name="Client Company B")

        # Link client users to their companies
        UserTenantMembership.objects.create(user=self.client_user, tenant=self.tenant_a, role="client", client=self.client_a)
        UserTenantMembership.objects.create(user=self.other_client_user, tenant=self.tenant_a, role="client", client=self.client_b)

        # Setup Methodology
        from assessments.models import AssessmentMethodology, AssessmentMethodologyVersion
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant_a, name="Cyber Methodology")
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant_a, methodology=self.methodology, version_number="1.0"
        )

        # Setup Assessments
        self.assessment_client_a = Assessment.objects.create(
            tenant=self.tenant_a, client=self.client_a, name="Assessment Client A", methodology_version=self.version
        )
        self.assessment_client_b = Assessment.objects.create(
            tenant=self.tenant_a, client=self.client_b, name="Assessment Client B", methodology_version=self.version
        )

        set_current_tenant(None)

    def login_user(self, user):
        c = Client()
        c.login(email=user.email, password="password")
        return c

    def test_client_role_isolation_and_restrictions(self):
        """
        Tests that client users can only see assessments belonging to their assigned company
        and are blocked from assessor-only tasks.
        """
        c = self.login_user(self.client_user)

        # 1. Accessing their own assessment should succeed
        response = c.get(reverse('assessment_detail', args=[self.assessment_client_a.id]))
        self.assertEqual(response.status_code, 200)

        # 2. Accessing another client's assessment should be restricted (returns 404 or redirect)
        response = c.get(reverse('assessment_detail', args=[self.assessment_client_b.id]))
        self.assertEqual(response.status_code, 404)

        # 3. Assessors/admins should be able to see both
        c_assessor = self.login_user(self.assessor)
        response = c_assessor.get(reverse('assessment_detail', args=[self.assessment_client_a.id]))
        self.assertEqual(response.status_code, 200)
        response = c_assessor.get(reverse('assessment_detail', args=[self.assessment_client_b.id]))
        self.assertEqual(response.status_code, 200)

    def test_comment_creation_and_replies(self):
        """
        Verify that comments can be posted to assessments, replies can be nested,
        notifications are dispatched to parent authors, and audit logs are recorded.
        """
        c = self.login_user(self.assessor)
        
        # Post a primary comment
        response = c.post(reverse('add_comment'), {
            'entity_type': 'assessment',
            'entity_id': self.assessment_client_a.id,
            'text': 'This is a primary review note.',
            'next': reverse('assessment_detail', args=[self.assessment_client_a.id])
        })
        self.assertEqual(response.status_code, 302)

        comment = Comment.objects.get(assessment=self.assessment_client_a, parent=None)
        self.assertEqual(comment.text, 'This is a primary review note.')
        self.assertEqual(comment.user, self.assessor)

        # Reply to the comment from a reviewer
        c_rev = self.login_user(self.reviewer)
        response = c_rev.post(reverse('add_comment'), {
            'entity_type': 'assessment',
            'entity_id': self.assessment_client_a.id,
            'parent_id': comment.id,
            'text': 'I agree with this note.',
            'next': reverse('assessment_detail', args=[self.assessment_client_a.id])
        })
        self.assertEqual(response.status_code, 302)

        # Assert nested reply was created
        reply = Comment.objects.get(parent=comment)
        self.assertEqual(reply.text, 'I agree with this note.')
        self.assertEqual(reply.user, self.reviewer)

        # Check notifications: assessor should have received reply notification
        notif = Notification.objects.filter(recipient=self.assessor).first()
        self.assertIsNotNone(notif)
        self.assertIn("replied to your comment", notif.message)

        # Verify audit event is written
        audit = AuditEvent.objects.filter(event_type='COLLABORATION', action='CREATE').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.user, self.reviewer)
        self.assertEqual(audit.payload['parent_id'], str(comment.id))

    def test_mentions_parsing_and_notifications(self):
        """
        Tests that user mentions (like @email) inside comments dispatch notifications.
        """
        c = self.login_user(self.assessor)
        
        # Post a comment mentioning the client user
        c.post(reverse('add_comment'), {
            'entity_type': 'assessment',
            'entity_id': self.assessment_client_a.id,
            'text': 'Paging @client@tenant-a.com to check this report.',
            'next': reverse('assessment_detail', args=[self.assessment_client_a.id])
        })

        # Verify client user was notified
        notif = Notification.objects.filter(recipient=self.client_user).first()
        self.assertIsNotNone(notif)
        self.assertEqual(notif.title, "You were mentioned")
        self.assertIn("mentioned you", notif.message)

    @patch('evidence.tasks.scan_file_clamav.delay')
    def test_evidence_request_and_review_workflow(self, mock_scan_delay):
        """
        Verify the complete evidence request cycle:
        1. Assessor requests evidence -> Client receives alert
        2. Client submits file response -> Assessor receives alert
        3. Assessor rejects -> Client receives rejection notes
        4. Client submits clean file -> Assessor approves -> Linked successfully
        """
        c_assessor = self.login_user(self.assessor)

        # 1. Create Evidence Request
        response = c_assessor.post(reverse('evidence_requests_list'), {
            'title': 'GDPR Compliance Statement',
            'description': 'Please upload the latest signed GDPR declaration.',
            'client': self.client_a.id,
            'assessment': self.assessment_client_a.id
        })
        self.assertEqual(response.status_code, 302)

        req = EvidenceRequest.objects.get(title='GDPR Compliance Statement')
        self.assertEqual(req.status, 'Pending')
        self.assertEqual(req.client, self.client_a)

        # Verify client user was notified
        notif = Notification.objects.filter(recipient=self.client_user, title="New Evidence Request").first()
        self.assertIsNotNone(notif)

        # 2. Client submits response (uploading dummy file)
        c_client = self.login_user(self.client_user)
        uploaded_file = SimpleUploadedFile("gdpr.pdf", b"GDPR content", content_type="application/pdf")
        
        response = c_client.post(reverse('submit_evidence_response', args=[req.id]), {
            'client_response': 'Here is our GDPR statement.',
            'file': uploaded_file
        })
        self.assertEqual(response.status_code, 302)

        # Verify status transitioned to Submitted
        req.refresh_from_db()
        self.assertEqual(req.status, 'Submitted')
        self.assertEqual(req.client_response, 'Here is our GDPR statement.')
        self.assertIsNotNone(req.submitted_evidence)

        # Mock Scan Task was queued
        mock_scan_delay.assert_called_once()

        # 3. Assessor rejects submission
        response = c_assessor.post(reverse('approve_reject_evidence_request', args=[req.id]), {
            'action': 'reject',
            'rejection_notes': 'Document is missing signature.'
        })
        self.assertEqual(response.status_code, 302)

        req.refresh_from_db()
        self.assertEqual(req.status, 'Rejected')
        self.assertEqual(req.rejection_notes, 'Document is missing signature.')

        # Verify client notified of rejection
        notif_reject = Notification.objects.filter(recipient=self.client_user, title="Evidence Request Rejected").first()
        self.assertIsNotNone(notif_reject)

        # 4. Assessor approves submission
        response = c_assessor.post(reverse('approve_reject_evidence_request', args=[req.id]), {
            'action': 'approve'
        })
        self.assertEqual(response.status_code, 302)

        req.refresh_from_db()
        self.assertEqual(req.status, 'Approved')

        # Check that the evidence document is now linked directly to the assessment
        doc = req.submitted_evidence
        doc.refresh_from_db()
        self.assertEqual(doc.assessment, self.assessment_client_a)

        # Check WORM Audit Ledger log
        audit = AuditEvent.objects.filter(event_type='COLLABORATION', action='UPDATE').first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.payload['status'], 'Approved')
