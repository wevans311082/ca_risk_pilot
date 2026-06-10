from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch, MagicMock
from accounts.models import User
from tenants.models import Tenant, UserTenantMembership, Client as TenantClient
from assessments.models import Assessment
from .models import EvidenceDocument, EvidenceVersion
from .tasks import scan_file_clamav, extract_text_task

class EvidenceSubsystemTests(TestCase):
    def setUp(self):
        # Create Tenants
        self.tenant_a = Tenant.objects.create(name="Tenant A", domain="tenant-a")
        self.tenant_b = Tenant.objects.create(name="Tenant B", domain="tenant-b")

        # Create Users with usernames
        self.admin_user = User.objects.create_user(username="admin", email="admin@tenant-a.com", password="password")
        self.std_user = User.objects.create_user(username="stduser", email="user@tenant-a.com", password="password")
        self.other_user = User.objects.create_user(username="otheruser", email="other@tenant-b.com", password="password")

        # Create Tenant Memberships
        UserTenantMembership.objects.create(user=self.admin_user, tenant=self.tenant_a, role="admin")
        UserTenantMembership.objects.create(user=self.std_user, tenant=self.tenant_a, role="assessor")
        UserTenantMembership.objects.create(user=self.other_user, tenant=self.tenant_b, role="admin")

        # Setup Client and Assessment
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        
        self.client_a = TenantClient.objects.create(tenant=self.tenant_a, name="Client A")
        
        # We need a methodology version for assessment
        from assessments.models import AssessmentMethodology, AssessmentMethodologyVersion
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant_a, name="Methodology A")
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant_a, methodology=self.methodology, version_number="1.0"
        )
        
        self.assessment = Assessment.objects.create(
            tenant=self.tenant_a,
            client=self.client_a,
            methodology_version=self.version,
            name="Test Assessment A"
        )
        set_current_tenant(None)

    def login_user(self, user, tenant):
        client = Client()
        client.login(email=user.email, password="password")
        return client

    @patch('evidence.tasks.scan_file_clamav.delay')
    def test_upload_evidence_document_and_quarantine(self, mock_scan_delay):
        """
        Verify uploading a new evidence document puts it in 'Pending' quarantine
        and triggers a Celery task scan.
        """
        client = self.login_user(self.admin_user, self.tenant_a)
        
        uploaded_file = SimpleUploadedFile("policy.pdf", b"Dummy PDF content", content_type="application/pdf")
        
        response = client.post(reverse('document_library'), {
            'name': 'Test Upload Doc',
            'file': uploaded_file,
            'assessment': self.assessment.id
        })
        
        self.assertEqual(response.status_code, 302)
        
        # Verify DB entry
        doc = EvidenceDocument.objects.get(name='Test Upload Doc')
        self.assertEqual(doc.tenant, self.tenant_a)
        
        version = doc.versions.first()
        self.assertIsNotNone(version)
        self.assertEqual(version.version_number, 1)
        self.assertEqual(version.status, 'Pending')  # Default quarantine status
        self.assertEqual(version.file_name, 'policy.pdf')
        
        # Celery task should be triggered
        mock_scan_delay.assert_called_once_with(version.id)

    def test_secure_download_quarantine_blocking(self):
        """
        Verify that downloading an infected or pending file returns 403 Forbidden.
        Only clean files should be downloaded.
        """
        # Create a document
        doc = EvidenceDocument.objects.create(tenant=self.tenant_a, name="Test Lock", created_by=self.admin_user)
        
        v_pending = EvidenceVersion.objects.create(
            document=doc, version_number=1, file_name="pending.pdf", file="pending.pdf", status="Pending", file_size=100
        )
        v_infected = EvidenceVersion.objects.create(
            document=doc, version_number=2, file_name="infected.pdf", file="infected.pdf", status="Infected", file_size=100
        )
        v_clean = EvidenceVersion.objects.create(
            document=doc, version_number=3, file_name="clean.pdf", file="clean.pdf", status="Clean", file_size=100
        )

        client = self.login_user(self.std_user, self.tenant_a)

        from auditlog.signing import generate_signed_url

        # 1. Download Pending: Should return 403
        response = client.get(generate_signed_url('download_file', args=[v_pending.id]))
        self.assertEqual(response.status_code, 403)

        # 2. Download Infected: Should return 403
        response = client.get(generate_signed_url('download_file', args=[v_infected.id]))
        self.assertEqual(response.status_code, 403)

        # 3. Download Clean: Should attempt download (FileNotFound since file path is fake, but not blocked by quarantine check)
        with patch('django.http.FileResponse') as mock_file_response:
            mock_file_response.return_value = MagicMock(status_code=200)
            response = client.get(generate_signed_url('download_file', args=[v_clean.id]))
            # Checks status or raises 404 (due to file.open raising FileNotFoundError, which view converts to 404)
            self.assertIn(response.status_code, [404, 200])

    def test_rbac_deletion_restrictions(self):
        """
        Verify that assessor/viewer users cannot delete evidence documents,
        but admin/owner can.
        """
        doc = EvidenceDocument.objects.create(tenant=self.tenant_a, name="Protected Document", created_by=self.admin_user)

        # Try to delete using std_user (assessor role)
        client_std = self.login_user(self.std_user, self.tenant_a)
        response = client_std.get(reverse('delete_document', args=[doc.id]))
        self.assertEqual(response.status_code, 302) # Redirects back with error message
        
        # Verify not deleted
        self.assertTrue(EvidenceDocument.objects.filter(id=doc.id).exists())

        # Try to delete using admin_user (admin role)
        client_admin = self.login_user(self.admin_user, self.tenant_a)
        response = client_admin.get(reverse('delete_document', args=[doc.id]))
        self.assertEqual(response.status_code, 302) # Success redirect
        
        # Verify soft-deleted (not returned in default manager queryset)
        self.assertFalse(EvidenceDocument.objects.filter(id=doc.id).exists())
        self.assertTrue(EvidenceDocument.unfiltered.filter(id=doc.id, is_deleted=True).exists())

    @patch('socket.socket')
    def test_clamav_scan_success(self, mock_socket):
        """
        Test the ClamAV scanning stream helper by mocking socket interactions.
        """
        from .tasks import scan_file_stream
        
        # Mock socket instance behavior
        mock_inst = MagicMock()
        mock_socket.return_value = mock_inst
        
        # Mock response from ClamAV: 'stream: OK'
        mock_inst.recv.side_effect = [b'stream: OK\n', b'']
        
        file_mock = MagicMock()
        file_mock.read.side_effect = [b'clean text chunk', b'']
        
        status, results = scan_file_stream(file_mock)
        self.assertEqual(status, 'Clean')
        self.assertEqual(results, 'No virus found.')

    @patch('socket.socket')
    def test_clamav_scan_infected(self, mock_socket):
        """
        Test the ClamAV scanning stream helper with an infected response.
        """
        from .tasks import scan_file_stream
        
        mock_inst = MagicMock()
        mock_socket.return_value = mock_inst
        
        # Mock response: 'stream: Eicar-Test-Signature FOUND'
        mock_inst.recv.side_effect = [b'stream: Eicar-Test-Signature FOUND\n', b'']
        
        file_mock = MagicMock()
        file_mock.read.side_effect = [b'malicious virus chunk', b'']
        
        status, results = scan_file_stream(file_mock)
        self.assertEqual(status, 'Infected')
        self.assertEqual(results, 'Eicar-Test-Signature')
