from django.test import TestCase, Client as HttpClient
from django.urls import reverse
from django.utils import timezone
from accounts.models import User
from tenants.models import Tenant, Client, UserTenantMembership
from assessments.models import (
    AssessmentMethodology, AssessmentMethodologyVersion,
    ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, LikelihoodCriteria,
    ImpactCriteria, ThreatCategory, Threat, CentralRisk, Assessment
)
from evidence.models import EvidenceDocument
from auditlog.models import AuditEvent
from assets.models import Asset

class AssetRegisterTestCase(TestCase):
    def setUp(self):
        self.http_client = HttpClient()
        
        # Create user
        self.user = User.objects.create_user(
            username='assessor@riskpilot.local', 
            email='assessor@riskpilot.local', 
            password='password123'
        )
        
        # Create tenant
        self.tenant = Tenant.objects.create(name='Test Corp', domain='testcorp')
        
        # Link user to tenant as assessor
        UserTenantMembership.objects.create(user=self.user, tenant=self.tenant, role='assessor')
        
        # Create clients
        self.client_a = Client.objects.create(tenant=self.tenant, name='Client A')
        self.client_b = Client.objects.create(tenant=self.tenant, name='Client B')
        
        # Create client users
        self.user_client_a = User.objects.create_user(
            username='clienta@riskpilot.local',
            email='clienta@riskpilot.local',
            password='password123'
        )
        UserTenantMembership.objects.create(
            user=self.user_client_a, tenant=self.tenant, role='client', client=self.client_a
        )
        
        self.user_client_b = User.objects.create_user(
            username='clientb@riskpilot.local',
            email='clientb@riskpilot.local',
            password='password123'
        )
        UserTenantMembership.objects.create(
            user=self.user_client_b, tenant=self.tenant, role='client', client=self.client_b
        )
        
        # Create methodology & version
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant, name='RP Method')
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant, methodology=self.methodology, version_number='1.0', is_active=True
        )
        
        # Scoring Lookup Helpers (for risk creation)
        self.freq_low = ThreatFrequencyCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='<1/year', score=1
        )
        self.prob_low = VulnerabilityProbabilityCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='<1%', score=1
        )
        self.impact_minor = ImpactCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Minor', score=2,
            description='Minor desc', financial_impact_range='< £50,000'
        )
        for i in range(1, 7):
            LikelihoodCriteria.objects.create(
                tenant=self.tenant, methodology_version=self.version, score_value=i, label=f"L-Label-{i}"
            )
        
        # Threat
        self.t_cat = ThreatCategory.objects.create(tenant=self.tenant, name='Technical Failures')
        self.threat = Threat.objects.create(tenant=self.tenant, category=self.t_cat, name='Hardware Failure')

    def test_asset_creation(self):
        """
        Verify assessors can create assets directly.
        """
        self.http_client.force_login(self.user)
        
        response = self.http_client.post(reverse('assets:asset_add'), {
            'client': self.client_a.id,
            'owner': self.user.id,
            'name': 'Oracle Accounting DB',
            'asset_type': 'Software',
            'supplier': 'Oracle Corp',
            'classification': 'Confidential',
            'location': 'Dublin DC',
            'criticality': 'High',
            'business_function': 'Billing',
            'description': 'Main Billing Database'
        })
        
        self.assertEqual(response.status_code, 302) # Redirect to detail page
        
        # Fetch from DB
        asset = Asset.objects.get(name='Oracle Accounting DB', tenant=self.tenant)
        self.assertEqual(asset.asset_type, 'Software')
        self.assertEqual(asset.criticality, 'High')
        self.assertEqual(asset.client, self.client_a)
        
        # Verify Audit Log
        audit_event = AuditEvent.objects.filter(tenant=self.tenant, event_type='ASSET', action='CREATE').first()
        self.assertIsNotNone(audit_event)
        self.assertEqual(audit_event.user, self.user)

    def test_client_isolation_boundaries(self):
        """
        Verify client role users are locked to their own company's assets.
        """
        # Create Asset A
        asset_a = Asset.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            name='Asset A',
            asset_type='Hardware',
            classification='Internal',
            criticality='Medium'
        )
        
        # Create Asset B
        asset_b = Asset.objects.create(
            tenant=self.tenant,
            client=self.client_b,
            name='Asset B',
            asset_type='Hardware',
            classification='Internal',
            criticality='Medium'
        )
        
        # 1. Log in as Client User A
        self.http_client.force_login(self.user_client_a)
        
        # Visit list page
        response = self.http_client.get(reverse('assets:asset_list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Asset A')
        self.assertNotContains(response, 'Asset B')
        
        # Access Asset A details
        response = self.http_client.get(reverse('assets:asset_detail', args=[asset_a.id]))
        self.assertEqual(response.status_code, 200)
        
        # Access Asset B details (should return 404)
        response = self.http_client.get(reverse('assets:asset_detail', args=[asset_b.id]))
        self.assertEqual(response.status_code, 404)
        
        # Try editing Asset A (should return 403 Forbidden)
        response = self.http_client.get(reverse('assets:asset_edit', args=[asset_a.id]))
        self.assertEqual(response.status_code, 403)

    def test_linkage_operations(self):
        """
        Verify linking Central Risks, Assessments, and Evidence documents works.
        """
        self.http_client.force_login(self.user)
        
        # Create Central Risk
        risk = CentralRisk.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            asset_name='Database Risk',
            threat=self.threat,
            vulnerability='Weak passwords',
            threat_frequency=self.freq_low,
            vulnerability_probability=self.prob_low,
            impact_severity=self.impact_minor
        )
        
        # Create Assessment
        assessment = Assessment.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            methodology_version=self.version,
            name='Q4 Audit'
        )
        
        # Create Evidence Document
        evidence = EvidenceDocument.objects.create(
            tenant=self.tenant,
            name='Auditor Checklist.pdf'
        )
        
        # Create Asset and link entities
        response = self.http_client.post(reverse('assets:asset_add'), {
            'client': self.client_a.id,
            'name': 'Linked Server Asset',
            'asset_type': 'Hardware',
            'classification': 'Internal',
            'criticality': 'Medium',
            'central_risks': [risk.id],
            'assessments': [assessment.id],
            'evidence_documents': [evidence.id]
        })
        self.assertEqual(response.status_code, 302)
        
        asset = Asset.objects.get(name='Linked Server Asset', tenant=self.tenant)
        self.assertIn(risk, asset.central_risks.all())
        self.assertIn(assessment, asset.assessments.all())
        self.assertIn(evidence, asset.evidence_documents.all())
        
        # Verify backlinks in templates/queries
        self.assertIn(asset, risk.linked_assets.all())
        self.assertIn(asset, assessment.linked_assets.all())
        self.assertIn(asset, evidence.linked_assets.all())

    def test_soft_deletion_safety(self):
        """
        Verify assets are soft deleted and hidden from directory list.
        """
        self.http_client.force_login(self.user)
        
        # Create Asset
        asset = Asset.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            name='Transient Asset',
            asset_type='Service',
            classification='Public',
            criticality='Low'
        )
        
        # Delete Asset
        response = self.http_client.post(reverse('assets:asset_delete', args=[asset.id]))
        self.assertEqual(response.status_code, 302)
        
        # Verify excluded by default manager
        self.assertFalse(Asset.objects.filter(id=asset.id).exists())
        
        # Verify Audit Log
        audit_event = AuditEvent.objects.filter(tenant=self.tenant, event_type='ASSET', action='DELETE').first()
        self.assertIsNotNone(audit_event)
