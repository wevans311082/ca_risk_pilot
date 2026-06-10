from django.test import TestCase, Client as HttpClient
from django.urls import reverse
from django.utils import timezone
import datetime
from accounts.models import User
from tenants.models import Tenant, Client, UserTenantMembership
from assessments.models import (
    AssessmentMethodology, AssessmentMethodologyVersion,
    ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, LikelihoodCriteria,
    ImpactCriteria, RiskCategory, ThreatCategory, Threat, Assessment, RiskItem,
    CentralRisk, RiskHistory
)

class CentralRiskRegisterTestCase(TestCase):
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
        
        # Create scoring lookup rules
        self.freq_low = ThreatFrequencyCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='<1/year', score=1
        )
        self.freq_high = ThreatFrequencyCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='1/month', score=3
        )
        
        self.prob_low = VulnerabilityProbabilityCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='<1%', score=1
        )
        self.prob_high = VulnerabilityProbabilityCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='20%', score=3
        )
        
        # Likelihood rules
        for i in range(1, 7):
            LikelihoodCriteria.objects.create(
                tenant=self.tenant, methodology_version=self.version, score_value=i, label=f"L-Label-{i}"
            )
            
        # Impact criteria
        self.impact_minor = ImpactCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Minor', score=2,
            description='Minor desc', financial_impact_range='< £50,000'
        )
        self.impact_major = ImpactCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Major', score=5,
            description='Major desc', financial_impact_range='> 20% of turnover'
        )
        
        # Risk Categories
        self.cat_low = RiskCategory.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Low', min_score=1, max_score=4
        )
        self.cat_med = RiskCategory.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Medium', min_score=5, max_score=15
        )
        self.cat_high = RiskCategory.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='High', min_score=16, max_score=30
        )
        
        # Threat library
        self.t_cat = ThreatCategory.objects.create(tenant=self.tenant, name='Technical Failures')
        self.threat = Threat.objects.create(tenant=self.tenant, category=self.t_cat, name='Hardware Failure')

    def test_independent_risk_creation(self):
        """
        Verify assessors can create central risks directly in the register.
        """
        self.http_client.force_login(self.user)
        
        # Create a central risk
        response = self.http_client.post(reverse('central_risk_add'), {
            'client': self.client_a.id,
            'owner': self.user.id,
            'asset_name': 'Core Accounting Database',
            'asset_location': 'AWS Ireland',
            'asset_owner': 'Lead DBA',
            'threat': self.threat.id,
            'vulnerability': 'SQL Injection vulnerabilities in legacy reports',
            'existing_controls': 'WAF is active',
            'confidentiality_affected': '1',
            'integrity_affected': '1',
            'threat_frequency': self.freq_high.id,
            'vulnerability_probability': self.prob_high.id,
            'impact_severity': self.impact_major.id,
            'status': 'Active',
            'review_date': '2026-12-31'
        })
        
        self.assertEqual(response.status_code, 302) # Redirects to detail view
        
        # Fetch risk from db
        risk = CentralRisk.objects.get(asset_name='Core Accounting Database', tenant=self.tenant)
        self.assertEqual(risk.status, 'Active')
        self.assertEqual(risk.risk_score, 30) # (3+3) * 5
        self.assertEqual(risk.risk_category, 'High')
        
        # Verify history is logged
        history = RiskHistory.objects.filter(risk=risk)
        self.assertEqual(history.count(), 1)
        self.assertEqual(history.first().action, 'Create')

    def test_client_role_isolation(self):
        """
        Verify client role users are isolated to their client company.
        """
        # Create a risk for Client A
        risk_a = CentralRisk.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            asset_name='Client A Risk',
            threat=self.threat,
            vulnerability='Vuln A',
            threat_frequency=self.freq_low,
            vulnerability_probability=self.prob_low,
            impact_severity=self.impact_minor,
            status='Active'
        )
        
        # Create a risk for Client B
        risk_b = CentralRisk.objects.create(
            tenant=self.tenant,
            client=self.client_b,
            asset_name='Client B Risk',
            threat=self.threat,
            vulnerability='Vuln B',
            threat_frequency=self.freq_low,
            vulnerability_probability=self.prob_low,
            impact_severity=self.impact_minor,
            status='Active'
        )

        # 1. Log in as Client User A and view list page
        self.http_client.force_login(self.user_client_a)
        response = self.http_client.get(reverse('central_risk_list'))
        self.assertEqual(response.status_code, 200)
        
        # Risk A should be visible, Risk B should not
        self.assertContains(response, 'Client A Risk')
        self.assertNotContains(response, 'Client B Risk')
        
        # 2. Try accessing Risk A detail page
        response = self.http_client.get(reverse('central_risk_detail', args=[risk_a.id]))
        self.assertEqual(response.status_code, 200)
        
        # 3. Try accessing Risk B detail page (should return 404)
        response = self.http_client.get(reverse('central_risk_detail', args=[risk_b.id]))
        self.assertEqual(response.status_code, 404)

        # 4. Try editing risk parameters as Client A (should return 403 Forbidden)
        response = self.http_client.get(reverse('central_risk_edit', args=[risk_a.id]))
        self.assertEqual(response.status_code, 403)

    def test_assessment_sync_workflow(self):
        """
        Verify that completing an assessment updates the linked CentralRisk records.
        """
        self.http_client.force_login(self.user)
        
        # Create a CentralRisk
        central_risk = CentralRisk.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            asset_name='Master Risk API',
            threat=self.threat,
            vulnerability='Outdated packages',
            threat_frequency=self.freq_low,
            vulnerability_probability=self.prob_low,
            impact_severity=self.impact_minor,
            status='Active'
        )
        
        # Create an Assessment in progress
        assessment = Assessment.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            methodology_version=self.version,
            name='Q2 Security Assessment',
            status='InProgress'
        )
        
        # Create a linked RiskItem under this assessment with updated scores
        risk_item = RiskItem.objects.create(
            tenant=self.tenant,
            assessment=assessment,
            central_risk=central_risk,
            asset_name='Master Risk API - Assessment Updated Name',
            asset_location='Local',
            asset_owner='Dev Team',
            threat=self.threat,
            vulnerability='Severe SQL Injection vulnerability discovered',
            existing_controls='None',
            threat_frequency=self.freq_high,
            vulnerability_probability=self.prob_high,
            impact_severity=self.impact_major,
            proposed_controls='Rewrite API calls',
            residual_threat_frequency=self.freq_low,
            residual_vulnerability_probability=self.prob_low,
            residual_impact_severity=self.impact_minor
        )
        
        # Complete the Assessment
        response = self.http_client.post(reverse('assessment_detail', args=[assessment.id]), {
            'update_status': '1',
            'status': 'Completed'
        })
        self.assertEqual(response.status_code, 302)
        
        # Reload Central Risk from DB and check synchronized values
        central_risk.refresh_from_db()
        self.assertEqual(central_risk.asset_name, 'Master Risk API - Assessment Updated Name')
        self.assertEqual(central_risk.vulnerability, 'Severe SQL Injection vulnerability discovered')
        self.assertEqual(central_risk.threat_frequency, self.freq_high)
        self.assertEqual(central_risk.vulnerability_probability, self.prob_high)
        self.assertEqual(central_risk.impact_severity, self.impact_major)
        self.assertEqual(central_risk.risk_score, 30)
        
        # Verify synchronization history was logged
        history = RiskHistory.objects.filter(risk=central_risk, action='Update')
        self.assertTrue(history.exists())
        self.assertIn("sync from assessment", history.first().description)

    def test_risk_item_cannot_link_central_risk_from_another_client(self):
        self.http_client.force_login(self.user)

        central_risk_b = CentralRisk.objects.create(
            tenant=self.tenant,
            client=self.client_b,
            asset_name='Client B Central Risk',
            threat=self.threat,
            vulnerability='Client B vulnerability',
            threat_frequency=self.freq_low,
            vulnerability_probability=self.prob_low,
            impact_severity=self.impact_minor,
            status='Active'
        )
        assessment_a = Assessment.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            methodology_version=self.version,
            name='Client A Assessment',
            status='InProgress'
        )

        response = self.http_client.post(reverse('risk_item_add', args=[assessment_a.id]), {
            'asset_name': 'Client A Asset',
            'asset_location': 'Client A Site',
            'asset_owner': 'Client A Owner',
            'threat': self.threat.id,
            'vulnerability': 'Client A vulnerability',
            'existing_controls': 'Client A controls',
            'threat_frequency': self.freq_low.id,
            'vulnerability_probability': self.prob_low.id,
            'impact_severity': self.impact_minor.id,
            'central_risk': central_risk_b.id,
        })

        self.assertEqual(response.status_code, 404)
        self.assertFalse(RiskItem.objects.filter(assessment=assessment_a, central_risk=central_risk_b).exists())

    def test_lifecycle_and_status_transitions(self):
        """
        Verify status transitions and acceptance field cleanups.
        """
        self.http_client.force_login(self.user)
        
        # Create a risk in Draft
        risk = CentralRisk.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            asset_name='Lifecycle Risk',
            threat=self.threat,
            vulnerability='Unpatched servers',
            threat_frequency=self.freq_high,
            vulnerability_probability=self.prob_high,
            impact_severity=self.impact_major,
            status='Draft'
        )
        
        # 1. Accept the risk using the view
        expiry_date = (timezone.now() + datetime.timedelta(days=365)).date().strftime('%Y-%m-%d')
        response = self.http_client.post(reverse('central_risk_accept', args=[risk.id]), {
            'acceptance_rationale': 'Compensating network segmentation controls in place.',
            'acceptance_expiry': expiry_date
        })
        self.assertEqual(response.status_code, 302)
        
        risk.refresh_from_db()
        self.assertEqual(risk.status, 'Accepted')
        self.assertEqual(risk.acceptance_status, 'Accepted')
        self.assertEqual(risk.accepted_by, self.user)
        self.assertEqual(risk.acceptance_rationale, 'Compensating network segmentation controls in place.')
        
        # Verify history log
        history_accept = RiskHistory.objects.filter(risk=risk, action='Acceptance').first()
        self.assertIsNotNone(history_accept)
        
        # 2. Perform a review that transitions status away from Accepted
        response = self.http_client.post(reverse('central_risk_review', args=[risk.id]), {
            'review_notes': 'Periodic review. Re-activating risk because network segmentation was disabled.',
            'next_review_date': '2026-12-31',
            'status': 'Active',
            'threat_frequency': self.freq_high.id,
            'vulnerability_probability': self.prob_high.id,
            'impact_severity': self.impact_major.id
        })
        self.assertEqual(response.status_code, 302)
        
        risk.refresh_from_db()
        self.assertEqual(risk.status, 'Active')
        
        # Acceptance fields should be cleaned up!
        self.assertEqual(risk.acceptance_status, 'None')
        self.assertIsNone(risk.accepted_by)
        self.assertIsNone(risk.acceptance_expiry)
        self.assertEqual(risk.acceptance_rationale, '')
        
        # Verify history log
        history_review = RiskHistory.objects.filter(risk=risk, action='Review').first()
        self.assertIsNotNone(history_review)

    def test_acceptance_expiry(self):
        """
        Verify that expired risk acceptances automatically transition status on load.
        """
        self.http_client.force_login(self.user)
        
        # Create a risk that has expired acceptance
        past_expiry = timezone.now().date() - datetime.timedelta(days=1)
        risk = CentralRisk.objects.create(
            tenant=self.tenant,
            client=self.client_a,
            asset_name='Expired Risk',
            threat=self.threat,
            vulnerability='Old SSL',
            threat_frequency=self.freq_low,
            vulnerability_probability=self.prob_low,
            impact_severity=self.impact_minor,
            status='Accepted',
            acceptance_status='Accepted',
            acceptance_expiry=past_expiry
        )
        
        # Fetch details to trigger evaluation
        response = self.http_client.get(reverse('central_risk_detail', args=[risk.id]))
        self.assertEqual(response.status_code, 200)
        
        # Verify risk status has automatically reverted
        risk.refresh_from_db()
        self.assertEqual(risk.status, 'Under Review')
        self.assertEqual(risk.acceptance_status, 'Expired')
        
        # Verify history entry exists
        history_expiry = RiskHistory.objects.filter(risk=risk, action='Expiry').first()
        self.assertIsNotNone(history_expiry)
        self.assertIn("Risk acceptance expired automatically", history_expiry.description)
