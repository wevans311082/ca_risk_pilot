from django.test import TestCase, Client
from django.urls import reverse
from accounts.models import User
from tenants.models import Tenant, UserTenantMembership, Client as TenantClient
from assessments.models import (
    Assessment, RiskItem, Threat, ThreatCategory, ThreatFrequencyCriteria,
    VulnerabilityProbabilityCriteria, ImpactCriteria, TemplateAssessment,
    AssessmentTemplate, TemplateSection, TemplateQuestion
)
from findings.models import Finding
from evidence.models import EvidenceDocument, EvidenceVersion
from .models import AISettings, AIInteraction
from .providers import get_provider, MockProvider, GeminiProvider, OpenAIProvider, OllamaProvider

class AIAssistSubsystemTests(TestCase):
    def setUp(self):
        # Create Tenants
        self.tenant_a = Tenant.objects.create(name="Tenant A", domain="tenant-a")
        self.tenant_b = Tenant.objects.create(name="Tenant B", domain="tenant-b")

        # Create Users
        self.user_a = User.objects.create_user(username="usera", email="user@tenant-a.com", password="password")
        self.user_b = User.objects.create_user(username="userb", email="user@tenant-b.com", password="password")

        # Create Memberships
        UserTenantMembership.objects.create(user=self.user_a, tenant=self.tenant_a, role="admin")
        UserTenantMembership.objects.create(user=self.user_b, tenant=self.tenant_b, role="admin")

        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)

        self.client_a = TenantClient.objects.create(tenant=self.tenant_a, name="Client A")

        # Setup Methodology
        from assessments.models import AssessmentMethodology, AssessmentMethodologyVersion
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant_a, name="Methodology A")
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant_a, methodology=self.methodology, version_number="1.0"
        )

        # Setup Criteria
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

        # Setup Assessment
        self.assessment = Assessment.objects.create(
            tenant=self.tenant_a,
            client=self.client_a,
            methodology_version=self.version,
            name="Assessment A"
        )

        # Setup Risk Item
        self.risk_item = RiskItem.objects.create(
            tenant=self.tenant_a,
            assessment=self.assessment,
            asset_name="Backup Server",
            asset_location="On-premise",
            asset_owner="Security Team",
            threat=self.threat,
            vulnerability="No fire suppression",
            existing_controls="Smoke detectors",
            threat_frequency=self.freq,
            vulnerability_probability=self.prob,
            impact_severity=self.imp
        )

        # Setup Finding
        self.finding = Finding.objects.create(
            tenant=self.tenant_a,
            assessment=self.assessment,
            risk_item=self.risk_item,
            title="Fire safety exposure",
            severity="Medium",
            status="Open"
        )

        # Setup Evidence
        self.evidence = EvidenceDocument.objects.create(
            tenant=self.tenant_a,
            name="Backup log",
            assessment=self.assessment
        )
        self.evidence_version = EvidenceVersion.objects.create(
            document=self.evidence,
            version_number=1,
            file_name="backup.log",
            file_size=1024,
            content_type="text/plain",
            uploaded_by=self.user_a,
            status="Clean",
            extracted_text="Backup executed successfully on 2026-06-08."
        )

        set_current_tenant(None)

    def login_user(self, user):
        client = Client()
        client.login(email=user.email, password="password")
        return client

    def test_provider_resolution(self):
        """
        Verify that configured active provider maps to appropriate provider subclass,
        and defaults cleanly to MockProvider when configuration details are missing.
        """
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)

        # 1. No setting configured -> returns MockProvider
        self.assertIsInstance(get_provider(self.tenant_a), MockProvider)

        # 2. Configured Gemini with no key -> returns MockProvider
        settings = AISettings.objects.create(tenant=self.tenant_a, provider="Gemini", api_key="")
        self.assertIsInstance(get_provider(self.tenant_a), MockProvider)

        # 3. Configured Gemini with key -> returns GeminiProvider
        settings.api_key = "secret_key"
        settings.save()
        self.assertIsInstance(get_provider(self.tenant_a), GeminiProvider)

        # 4. Configured OpenAI with key -> returns OpenAIProvider
        settings.provider = "OpenAI"
        settings.save()
        self.assertIsInstance(get_provider(self.tenant_a), OpenAIProvider)

        # 5. Configured Ollama -> returns OllamaProvider
        settings.provider = "Ollama"
        settings.api_url = "http://localhost:11434"
        settings.save()
        self.assertIsInstance(get_provider(self.tenant_a), OllamaProvider)

        set_current_tenant(None)

    def test_ai_settings_view_update(self):
        """
        Verify that admin users can view and update AI settings correctly.
        """
        client = self.login_user(self.user_a)
        response = client.get(reverse('ai_settings'))
        self.assertEqual(response.status_code, 200)

        # Submit update form
        response = client.post(reverse('ai_settings'), {
            'provider': 'OpenAI',
            'api_key': 'open-ai-api-key',
            'api_url': '',
            'model_name': 'gpt-4o'
        })
        self.assertEqual(response.status_code, 302) # Redirects back

        # Verify saved state
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        settings = AISettings.objects.get(tenant=self.tenant_a)
        self.assertEqual(settings.provider, "OpenAI")
        self.assertEqual(settings.api_key, "open-ai-api-key")
        self.assertEqual(settings.model_name, "gpt-4o")
        set_current_tenant(None)

    def test_generate_ai_suggestion_unauthenticated(self):
        """
        Ensure unauthenticated requests are rejected.
        """
        client = Client()
        response = client.post(reverse('generate_ai_suggestion'), {})
        self.assertEqual(response.status_code, 302) # Redirects to login

    def test_generate_ai_suggestion_endpoints(self):
        """
        Validate execution paths for all 8 core AI features via the API endpoint.
        """
        client = self.login_user(self.user_a)

        # 1. Rationale Generation
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'rationale_generation',
            'risk_item_id': self.risk_item.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("risk score is justified", data['suggestion'])

        # 2. Finding Suggestions
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'finding_suggestions',
            'risk_item_id': self.risk_item.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("Title:", data['suggestion'])

        # 3. Recommendation Suggestions
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'recommendation_suggestions',
            'finding_id': self.finding.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("Recommendation:", data['suggestion'])

        # 4. Control Recommendations
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'control_recommendations',
            'risk_item_id': self.risk_item.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("MFA", data['suggestion'])

        # 5. Evidence Summarisation
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'evidence_summarisation',
            'evidence_id': self.evidence.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("backup retention schedule", data['suggestion'])

        # 6. Missing Control Identification
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'missing_control_identification',
            'risk_item_id': self.risk_item.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("UPS", data['suggestion'])

        # 7. Assessment Completeness Review
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'completeness_review',
            'assessment_id': self.assessment.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("complete", data['suggestion'])

        # 8. Contradiction Detection
        res = client.post(reverse('generate_ai_suggestion'), {
            'feature': 'contradiction_detection',
            'assessment_id': self.assessment.id
        }, content_type='application/json')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data['status'], 'success')
        self.assertIn("Contradiction", data['suggestion'])

        # Verify that AI Interactions are logged in the database
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        log_count = AIInteraction.objects.filter(tenant=self.tenant_a).count()
        self.assertEqual(log_count, 8)
        set_current_tenant(None)

    def test_ai_history_view(self):
        """
        Verify that AI history logs are successfully rendered in the audit template.
        """
        # Create an interaction log
        from tenants.isolation import set_current_tenant
        set_current_tenant(self.tenant_a)
        AIInteraction.objects.create(
            tenant=self.tenant_a,
            user=self.user_a,
            feature="rationale_generation",
            prompt="Prompt",
            response="Response",
            model_used="MockModel"
        )
        set_current_tenant(None)

        client = self.login_user(self.user_a)
        response = client.get(reverse('ai_history'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "rationale_generation")
        self.assertContains(response, "MockModel")
