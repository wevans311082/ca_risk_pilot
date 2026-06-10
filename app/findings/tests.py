from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch
from accounts.models import User
from tenants.models import Tenant, UserTenantMembership, Client as TenantClient
from assessments.models import Assessment, RiskItem, RiskTreatment, Threat, ThreatCategory, ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, ImpactCriteria
from evidence.models import EvidenceDocument
from .models import Finding, Recommendation

class FindingsSubsystemTests(TestCase):
    def setUp(self):
        # Create Tenants
        self.tenant_a = Tenant.objects.create(name="Tenant A", domain="tenant-a")
        self.tenant_b = Tenant.objects.create(name="Tenant B", domain="tenant-b")

        # Create Users with usernames
        self.user_a = User.objects.create_user(username="usera", email="user@tenant-a.com", password="password")
        self.user_b = User.objects.create_user(username="userb", email="user@tenant-b.com", password="password")

        # Create Memberships
        UserTenantMembership.objects.create(user=self.user_a, tenant=self.tenant_a, role="admin")
        UserTenantMembership.objects.create(user=self.user_b, tenant=self.tenant_b, role="admin")

        # Build basic methodology and threat structure under tenant_a (for risk items)
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        
        self.client_a = TenantClient.objects.create(tenant=self.tenant_a, name="Client A")
        
        # Setup dummy assessment
        from assessments.models import AssessmentMethodology, AssessmentMethodologyVersion
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant_a, name="Methodology A")
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant_a, methodology=self.methodology, version_number="1.0"
        )
        
        # Setup criteria
        self.freq = ThreatFrequencyCriteria.objects.create(
            tenant=self.tenant_a, methodology_version=self.version, label="Low", score=1
        )
        self.prob = VulnerabilityProbabilityCriteria.objects.create(
            tenant=self.tenant_a, methodology_version=self.version, label="Low", score=1
        )
        self.imp = ImpactCriteria.objects.create(
            tenant=self.tenant_a, methodology_version=self.version, label="Low", score=1
        )
        
        # Setup Threat
        tc = ThreatCategory.objects.create(tenant=self.tenant_a, name="Technical Failures")
        self.threat = Threat.objects.create(tenant=self.tenant_a, category=tc, name="System Crash")

        self.assessment = Assessment.objects.create(
            tenant=self.tenant_a,
            client=self.client_a,
            methodology_version=self.version,
            name="Assessment A"
        )
        
        # Setup RiskItem
        self.risk_item = RiskItem.objects.create(
            tenant=self.tenant_a,
            assessment=self.assessment,
            asset_name="Server",
            asset_location="Data Center",
            asset_owner="IT",
            threat=self.threat,
            vulnerability="No backups",
            existing_controls="Firewall",
            threat_frequency=self.freq,
            vulnerability_probability=self.prob,
            impact_severity=self.imp
        )

        set_current_tenant(None)

    def login_user(self, user):
        client = Client()
        client.login(email=user.email, password="password")
        return client

    def test_create_finding_with_inline_recommendation(self):
        """
        Verify that posting data to finding_create creates a Finding,
        links it to an Assessment/RiskItem, attaches evidence,
        and creates an inline Recommendation.
        """
        client = self.login_user(self.user_a)

        # Create mock evidence document to link
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        evidence = EvidenceDocument.objects.create(tenant=self.tenant_a, name="System Log evidence")
        set_current_tenant(None)

        response = client.post(reverse('finding_create'), {
            'title': 'Server Vulnerability Finding',
            'description': 'Description of gap',
            'severity': 'High',
            'status': 'Open',
            'assessment': self.assessment.id,
            'risk_item': self.risk_item.id,
            'due_date': '2026-12-31',
            'evidence': [evidence.id],
            # Recommendation
            'rec_text': 'Implement nightly backups',
            'rec_priority': 'High',
            'rec_effort': 'Medium',
            'rec_cost_estimate': '1500.00'
        })

        self.assertEqual(response.status_code, 302)  # Success redirect to findings list

        # Verify Finding is created
        finding = Finding.objects.get(title='Server Vulnerability Finding')
        self.assertEqual(finding.tenant, self.tenant_a)
        self.assertEqual(finding.severity, 'High')
        self.assertEqual(finding.status, 'Open')
        self.assertEqual(finding.assessment, self.assessment)
        self.assertEqual(finding.risk_item, self.risk_item)
        self.assertIn(evidence, finding.evidence.all())

        # Verify inline Recommendation is created
        rec = finding.recommendations.first()
        self.assertIsNotNone(rec)
        self.assertEqual(rec.text, 'Implement nightly backups')
        self.assertEqual(rec.priority, 'High')
        self.assertEqual(rec.effort, 'Medium')
        self.assertEqual(rec.cost_estimate, 1500.00)

    def test_tenant_isolation_findings(self):
        """
        Ensure user in Tenant B cannot view or edit findings from Tenant A.
        """
        # Create Finding in Tenant A
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        finding = Finding.objects.create(
            tenant=self.tenant_a,
            assessment=self.assessment,
            title="Tenant A Private Finding",
            severity="Medium",
            status="Open"
        )
        set_current_tenant(None)

        # Login as User B (Tenant B)
        client_b = self.login_user(self.user_b)

        # Try to view the edit page: should return 404
        response = client_b.get(reverse('finding_edit', args=[finding.id]))
        self.assertEqual(response.status_code, 404)

        # Try to view finding list: should NOT display Tenant A's finding
        response = client_b.get(reverse('finding_list'))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Tenant A Private Finding")

    def test_finding_soft_delete(self):
        """
        Verify that deleting a finding soft-deletes the record.
        """
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        finding = Finding.objects.create(
            tenant=self.tenant_a,
            assessment=self.assessment,
            title="Finding to Delete",
            severity="Low",
            status="Open"
        )
        set_current_tenant(None)

        client = self.login_user(self.user_a)
        response = client.get(reverse('finding_delete', args=[finding.id]))
        self.assertEqual(response.status_code, 302)

        # Check soft-deleted
        self.assertFalse(Finding.objects.filter(id=finding.id).exists())
        self.assertTrue(Finding.unfiltered.filter(id=finding.id, is_deleted=True).exists())

    def test_dashboard_roc_widget_statistics(self):
        """
        Verify that ROC metrics like Open Findings and Overdue Treatments
        are calculated correctly and sent to the dashboard.
        """
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        
        # Create an open finding
        Finding.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, title="Open F", severity="High", status="Open"
        )
        # Create a resolved finding (should not count as Open)
        Finding.objects.create(
            tenant=self.tenant_a, assessment=self.assessment, title="Resolved F", severity="High", status="Resolved"
        )
        
        # Create an overdue treatment (target date in the past, status not mitigated/closed/accepted)
        import datetime
        overdue_date = datetime.date.today() - datetime.timedelta(days=5)
        
        # We need a Treatment Action for risk_item
        # Note: RiskTreatment is a OneToOneField on RiskItem
        # Since self.risk_item already exists, let's create a treatment for it
        RiskTreatment.objects.create(
            tenant=self.tenant_a,
            risk_item=self.risk_item,
            action="Implement encryption",
            owner="Alice",
            target_date=overdue_date,
            status="Open"
        )
        
        set_current_tenant(None)

        client = self.login_user(self.user_a)
        response = client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)

        # Check metrics in context
        self.assertEqual(response.context['open_findings_count'], 1)
        self.assertEqual(response.context['overdue_treatments_count'], 1)
        
        # Verify lists are in context
        self.assertTrue(any(f.title == "Open F" for f in response.context['open_findings']))
        self.assertTrue(any(t.action == "Implement encryption" for t in response.context['overdue_treatments']))
