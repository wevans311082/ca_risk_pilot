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
from findings.models import Finding, Recommendation
from auditlog.models import AuditEvent
from controls.models import Control

class ControlLibraryTestCase(TestCase):
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
        
        # Scoring Lookup Helpers
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

    def test_control_creation(self):
        """
        Verify assessors can create controls.
        """
        self.http_client.force_login(self.user)
        
        response = self.http_client.post(reverse('controls:control_add'), {
            'client': self.client_a.id,
            'name': 'Automated Patching',
            'control_type': 'Technical',
            'description': 'OS systems auto patching policy',
            'effectiveness': 'Satisfactory',
            'maturity': 'Defined',
            'last_tested_at': '2026-01-01',
            'next_test_date': '2026-07-01'
        })
        
        self.assertEqual(response.status_code, 302) # Redirect to detail
        
        control = Control.objects.get(name='Automated Patching', tenant=self.tenant)
        self.assertEqual(control.control_type, 'Technical')
        self.assertEqual(control.effectiveness, 'Satisfactory')
        self.assertEqual(control.maturity, 'Defined')
        
        # Verify Audit Event
        audit_event = AuditEvent.objects.filter(tenant=self.tenant, event_type='CONTROL', action='CREATE').first()
        self.assertIsNotNone(audit_event)

    def test_client_scoping_isolation(self):
        """
        Verify client users can only see their client company controls.
        """
        # Control A
        control_a = Control.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            name='Control A',
            control_type='Administrative',
            effectiveness='Satisfactory',
            maturity='Defined'
        )
        # Control B
        control_b = Control.objects.create(
            tenant=self.tenant,
            client=self.client_b,
            name='Control B',
            control_type='Administrative',
            effectiveness='Satisfactory',
            maturity='Defined'
        )
        
        self.http_client.force_login(self.user_client_a)
        
        # List controls
        response = self.http_client.get(reverse('controls:control_list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Control A')
        self.assertNotContains(response, 'Control B')
        
        # Get details
        response = self.http_client.get(reverse('controls:control_detail', args=[control_a.id]))
        self.assertEqual(response.status_code, 200)
        
        # Blocked get detail Control B
        response = self.http_client.get(reverse('controls:control_detail', args=[control_b.id]))
        self.assertEqual(response.status_code, 404)
        
        # Blocked edit Control A (clients cannot edit)
        response = self.http_client.get(reverse('controls:control_edit', args=[control_a.id]))
        self.assertEqual(response.status_code, 403)

    def test_multi_entity_linkages(self):
        """
        Verify linking controls to risks, assessments, findings, and recommendations.
        """
        self.http_client.force_login(self.user)
        
        # Central Risk
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
        
        # Assessment
        assessment = Assessment.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            methodology_version=self.version,
            name='Q4 Audit'
        )
        
        # Finding
        finding = Finding.objects.create(
            tenant=self.tenant,
            assessment=assessment,
            title='Weak Passwords Policy',
            severity='Medium',
            status='Open'
        )
        
        # Recommendation
        recommendation = Recommendation.objects.create(
            tenant=self.tenant,
            finding=finding,
            text='Update policy to 12 chars minimum',
            priority='High',
            effort='Low'
        )
        
        # Create control and link
        response = self.http_client.post(reverse('controls:control_add'), {
            'client': self.client_a.id,
            'name': 'Password Policy Control',
            'control_type': 'Administrative',
            'effectiveness': 'Satisfactory',
            'maturity': 'Defined',
            'central_risks': [risk.id],
            'assessments': [assessment.id],
            'findings': [finding.id],
            'recommendations': [recommendation.id]
        })
        self.assertEqual(response.status_code, 302)
        
        control = Control.objects.get(name='Password Policy Control', tenant=self.tenant)
        self.assertIn(risk, control.central_risks.all())
        self.assertIn(assessment, control.assessments.all())
        self.assertIn(finding, control.findings.all())
        self.assertIn(recommendation, control.recommendations.all())
        
        # Verify backlinks
        self.assertIn(control, risk.linked_controls.all())
        self.assertIn(control, assessment.linked_controls.all())
        self.assertIn(control, finding.linked_controls.all())
        self.assertIn(control, recommendation.linked_controls.all())

    def test_soft_deletion_safety(self):
        """
        Verify controls are soft deleted and hidden.
        """
        self.http_client.force_login(self.user)
        
        control = Control.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            name='Transient Control',
            control_type='Physical',
            effectiveness='NotTested',
            maturity='Initial'
        )
        
        # Delete
        response = self.http_client.post(reverse('controls:control_delete', args=[control.id]))
        self.assertEqual(response.status_code, 302)
        
        # Excluded
        self.assertFalse(Control.objects.filter(id=control.id).exists())
        
        # Verify Audit Event
        audit_event = AuditEvent.objects.filter(tenant=self.tenant, event_type='CONTROL', action='DELETE').first()
        self.assertIsNotNone(audit_event)
