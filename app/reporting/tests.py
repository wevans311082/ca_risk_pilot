from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.base import ContentFile
from django.utils import timezone
from unittest.mock import patch, MagicMock
from accounts.models import User
from tenants.models import Tenant, UserTenantMembership, Client as TenantClient
from assessments.models import (
    Assessment, RiskItem, RiskTreatment, Threat, ThreatCategory,
    ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, ImpactCriteria,
    AssessmentMethodology, AssessmentMethodologyVersion
)
from reporting.models import ReportDocument, ReportVersion, ReportDownloadHistory
from reporting.tasks import generate_report_task, scan_report_clamav

class ReportingSubsystemTests(TestCase):
    def setUp(self):
        # Create Tenants
        self.tenant_a = Tenant.objects.create(name="Tenant A", domain="tenant-a")
        self.tenant_b = Tenant.objects.create(name="Tenant B", domain="tenant-b")

        # Create Users
        self.admin_user_a = User.objects.create_user(username="admina", email="admin@tenant-a.com", password="password")
        self.std_user_a = User.objects.create_user(username="stda", email="user@tenant-a.com", password="password")
        self.user_b = User.objects.create_user(username="userb", email="user@tenant-b.com", password="password")

        # Tenant memberships
        UserTenantMembership.objects.create(user=self.admin_user_a, tenant=self.tenant_a, role="admin")
        UserTenantMembership.objects.create(user=self.std_user_a, tenant=self.tenant_a, role="assessor")
        UserTenantMembership.objects.create(user=self.user_b, tenant=self.tenant_b, role="admin")

        # Setup Scope for Assessment
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)

        self.client_a = TenantClient.objects.create(tenant=self.tenant_a, name="Client A")
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant_a, name="Methodology A")
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant_a, methodology=self.methodology, version_number="1.0"
        )
        
        self.freq = ThreatFrequencyCriteria.objects.create(
            tenant=self.tenant_a, methodology_version=self.version, label="High", score=3
        )
        self.prob = VulnerabilityProbabilityCriteria.objects.create(
            tenant=self.tenant_a, methodology_version=self.version, label="Medium", score=2
        )
        self.imp = ImpactCriteria.objects.create(
            tenant=self.tenant_a, methodology_version=self.version, label="High", score=4
        )
        
        tc = ThreatCategory.objects.create(tenant=self.tenant_a, name="Physical Damage")
        self.threat = Threat.objects.create(tenant=self.tenant_a, category=tc, name="Fire")

        self.assessment = Assessment.objects.create(
            tenant=self.tenant_a,
            client=self.client_a,
            methodology_version=self.version,
            name="Infrastructure Assessment A",
            change_request="CR-101",
            business_process_impact="Critical Server Room operations"
        )

        self.risk_item = RiskItem.objects.create(
            tenant=self.tenant_a,
            assessment=self.assessment,
            asset_name="Server Rack 1",
            asset_location="Suite 4",
            asset_owner="IT Systems Group",
            threat=self.threat,
            vulnerability="Dry fire suppression empty",
            existing_controls="Fire doors",
            threat_frequency=self.freq,
            vulnerability_probability=self.prob,
            impact_severity=self.imp
        )

        set_current_tenant(None)

    def login_user(self, user):
        client = Client()
        client.login(email=user.email, password="password")
        return client

    @patch('reporting.views.generate_report_task.delay')
    def test_generate_report_queues_celery_task(self, mock_task_delay):
        """
        Verify requesting a report creates ReportDocument/ReportVersion and dispatches Celery task.
        """
        client = self.login_user(self.admin_user_a)

        response = client.post(reverse('generate_report'), {
            'assessment': self.assessment.id,
            'report_type': 'DetailedRiskAssessment',
            'file_format': 'PDF'
        })

        # Redirect back to referee
        self.assertEqual(response.status_code, 302)

        # Check DB entries
        doc = ReportDocument.objects.get(assessment=self.assessment, report_type='DetailedRiskAssessment')
        self.assertEqual(doc.tenant, self.tenant_a)
        self.assertEqual(doc.file_format, 'PDF')

        ver = doc.versions.first()
        self.assertIsNotNone(ver)
        self.assertEqual(ver.version_number, 1)
        self.assertEqual(ver.status, 'Pending')

        mock_task_delay.assert_called_once_with(ver.id)

    @patch('reporting.tasks.scan_report_clamav.delay')
    def test_celery_report_generators_pdf_docx_xlsx(self, mock_scan_delay):
        """
        Test that running generate_report_task synchronously executes generator code
        and attaches binary payloads for all formats.
        """
        # PDF format
        doc_pdf = ReportDocument.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, report_type='ExecutiveSummary', file_format='PDF'
        )
        ver_pdf = ReportVersion.objects.create(document=doc_pdf, version_number=1, status='Pending')
        
        res = generate_report_task(ver_pdf.id)
        self.assertIn("successfully generated", res)
        
        ver_pdf.refresh_from_db()
        self.assertEqual(ver_pdf.status, 'Pending')
        self.assertTrue(ver_pdf.file.name.endswith('.pdf'))
        self.assertTrue(ver_pdf.file.size > 0)
        mock_scan_delay.assert_called_once_with(ver_pdf.id)

        # DOCX format
        mock_scan_delay.reset_mock()
        doc_docx = ReportDocument.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, report_type='RiskRegister', file_format='DOCX'
        )
        ver_docx = ReportVersion.objects.create(document=doc_docx, version_number=1, status='Pending')
        
        res_docx = generate_report_task(ver_docx.id)
        self.assertIn("successfully generated", res_docx)
        
        ver_docx.refresh_from_db()
        self.assertTrue(ver_docx.file.name.endswith('.docx'))
        mock_scan_delay.assert_called_once_with(ver_docx.id)

        # XLSX format
        mock_scan_delay.reset_mock()
        doc_xlsx = ReportDocument.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, report_type='TreatmentPlan', file_format='XLSX'
        )
        ver_xlsx = ReportVersion.objects.create(document=doc_xlsx, version_number=1, status='Pending')
        
        res_xlsx = generate_report_task(ver_xlsx.id)
        self.assertIn("successfully generated", res_xlsx)
        
        ver_xlsx.refresh_from_db()
        self.assertTrue(ver_xlsx.file.name.endswith('.xlsx'))
        mock_scan_delay.assert_called_once_with(ver_xlsx.id)

    @patch('socket.socket')
    def test_clamav_scanning_for_reports(self, mock_socket):
        """
        Verify that scan_report_clamav runs socket checks and correctly flags clean vs infected reports.
        """
        doc = ReportDocument.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, report_type='ExecutiveSummary', file_format='PDF'
        )
        ver = ReportVersion.objects.create(document=doc, version_number=1, status='Pending')
        ver.file.save("dummy.pdf", ContentFile(b"clean data stream"))

        # 1. Clean Scan Mock
        mock_inst = MagicMock()
        mock_socket.return_value = mock_inst
        mock_inst.recv.side_effect = [b'stream: OK\n', b'']

        scan_report_clamav(ver.id)
        ver.refresh_from_db()
        self.assertEqual(ver.status, 'Clean')

        # 2. Infected Scan Mock
        ver.status = 'Pending'
        ver.save()
        mock_inst.recv.side_effect = [b'stream: Eicar-Signature FOUND\n', b'']
        
        scan_report_clamav(ver.id)
        ver.refresh_from_db()
        self.assertEqual(ver.status, 'Infected')
        self.assertIn("Malware Scan Alert", ver.error_message)

    def test_secure_download_and_history_logging(self):
        """
        Ensure unverified reports block downloads, and downloading a clean report logs download history.
        """
        doc = ReportDocument.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, report_type='ExecutiveSummary', file_format='PDF'
        )
        
        ver_pending = ReportVersion.objects.create(document=doc, version_number=1, status='Pending')
        ver_clean = ReportVersion.objects.create(document=doc, version_number=2, status='Clean')
        ver_clean.file.save("report.pdf", ContentFile(b"PDF mock binary"))

        client = self.login_user(self.std_user_a)

        from auditlog.signing import generate_signed_url

        # Download Pending: Blocked (403)
        url_pending = generate_signed_url('download_report', args=[ver_pending.id])
        response = client.get(url_pending)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ReportDownloadHistory.objects.filter(version=ver_pending).exists())

        # Download Clean: Allowed (200) and log audit history
        url_clean = generate_signed_url('download_report', args=[ver_clean.id])
        response = client.get(url_clean)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(ReportDownloadHistory.objects.filter(version=ver_clean, downloaded_by=self.std_user_a).exists())

    def test_rbac_report_soft_delete(self):
        """
        Check that assessor/viewers are blocked from soft-deleting reports, while admin/owners are allowed.
        """
        doc = ReportDocument.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, report_type='ExecutiveSummary', file_format='PDF'
        )

        # Standard Assessor tries to delete -> Denied
        client_std = self.login_user(self.std_user_a)
        response = client_std.get(reverse('delete_report', args=[doc.id]))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ReportDocument.objects.filter(id=doc.id).exists())

        # Admin tries to delete -> Allowed
        client_admin = self.login_user(self.admin_user_a)
        response = client_admin.get(reverse('delete_report', args=[doc.id]))
        self.assertEqual(response.status_code, 302)
        
        # Verify soft-deleted
        self.assertFalse(ReportDocument.objects.filter(id=doc.id).exists())
        self.assertTrue(ReportDocument.unfiltered.filter(id=doc.id, is_deleted=True).exists())

    def test_tenant_isolation_reports(self):
        """
        Ensure users from Tenant B cannot access or edit reports in Tenant A.
        """
        doc = ReportDocument.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, report_type='RiskRegister', file_format='PDF'
        )
        ver = ReportVersion.objects.create(document=doc, version_number=1, status='Clean')
        ver.file.save("reg.pdf", ContentFile(b"PDF contents"))

        client_b = self.login_user(self.user_b)

        from auditlog.signing import generate_signed_url
        # Try download Tenant A report: Should return 404 (due to get_object_or_404 filter on tenant)
        url = generate_signed_url('download_report', args=[ver.id])
        response = client_b.get(url)
        self.assertEqual(response.status_code, 404)

        # Try delete Tenant A report: Should return 404
        response = client_b.get(reverse('delete_report', args=[doc.id]))
        self.assertEqual(response.status_code, 404)
