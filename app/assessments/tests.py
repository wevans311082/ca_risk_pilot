from django.test import TestCase, Client as HttpClient
from django.urls import reverse
from datetime import date
from accounts.models import User
from tenants.models import Tenant, Client, UserTenantMembership
from assessments.models import (
    AssessmentMethodology, AssessmentMethodologyVersion,
    ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, LikelihoodCriteria,
    ImpactCriteria, RiskCategory, ThreatCategory, Threat, Assessment, RiskItem, RiskTreatment,
    AssessmentTemplate, TemplateSection, TemplateQuestion, QuestionChoice,
    TemplateScoringRange, TemplateAssessment, TemplateAnswer
)

class RiskRegisterWorkflowTestCase(TestCase):
    def setUp(self):
        self.http_client = HttpClient()
        
        # Create user
        self.user = User.objects.create_user(
            username='tester@riskpilot.local', 
            email='tester@riskpilot.local', 
            password='password123'
        )
        
        # Create tenant
        self.tenant = Tenant.objects.create(name='Test Corp', domain='testcorp')
        
        # Link user to tenant
        UserTenantMembership.objects.create(user=self.user, tenant=self.tenant, role='admin')
        
        # Create client
        self.client_org = Client.objects.create(tenant=self.tenant, name='Acme Co')
        
        # Create methodology & version
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant, name='RP Method')
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant, methodology=self.methodology, version_number='1.0'
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

    def test_dashboard_view(self):
        """
        Verify the dashboard loads successfully.
        """
        self.http_client.force_login(self.user)
        response = self.http_client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Corp')

    def test_create_assessment(self):
        """
        Verify starting an assessment run.
        """
        self.http_client.force_login(self.user)
        response = self.http_client.post(reverse('create_assessment'), {
            'name': 'Infrastructure Audit',
            'client': self.client_org.id,
            'methodology_version': self.version.id,
            'change_request': 'CR-100',
            'asset': 'Database',
            'location': 'AWS',
            'owner': 'CISO'
        })
        self.assertEqual(response.status_code, 302)
        
        # Verify database creation
        assessment = Assessment.objects.filter(name='Infrastructure Audit', tenant=self.tenant).first()
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.change_request, 'CR-100')

    def test_risk_item_workflow_and_scoring(self):
        """
        Verify adding a risk item, checking automatic score and category calculations,
        setting treatment, and calculating residual risk ratings.
        """
        self.http_client.force_login(self.user)
        
        # Create Assessment run
        assessment = Assessment.objects.create(
            tenant=self.tenant,
            client=self.client_org,
            methodology_version=self.version,
            name='Test Audit',
            status='InProgress'
        )
        
        # POST new risk item
        add_url = reverse('rp-assessments:risk_item_add' if ':' in reverse('dashboard') else 'risk_item_add', kwargs={'assessment_id': assessment.id})
        response = self.http_client.post(add_url, {
            'asset_name': 'PII server',
            'asset_location': 'Local server room',
            'asset_owner': 'SysAdmin',
            'threat': self.threat.id,
            'vulnerability': 'Unpatched OS',
            'existing_controls': 'WAF enabled',
            'confidentiality_affected': '1',
            'threat_frequency': self.freq_high.id,          # score = 3
            'vulnerability_probability': self.prob_high.id,  # score = 3 -> combined Likelihood = 6
            'impact_severity': self.impact_major.id,        # score = 5 -> inherent risk score = 30 (High)
            
            # Proposed treatment & residual scoring
            'proposed_controls': 'OS patching',
            'residual_threat_frequency': self.freq_low.id,          # score = 1
            'residual_vulnerability_probability': self.prob_low.id,  # score = 1 -> combined Likelihood = 2
            'residual_impact_severity': self.impact_minor.id,       # score = 2 -> residual risk score = 4 (Low)
            
            # Treatment Plan Fields
            'treatment_action': 'Patch system OS weekly',
            'treatment_owner': 'SysAdmin',
            'treatment_target_date': '2026-08-01',
            'treatment_status': 'In Progress',
            'treatment_notes': 'Awaiting downtime window'
        })
        self.assertEqual(response.status_code, 302)
        
        # Verify Inherent and Residual calculations
        item = RiskItem.objects.get(assessment=assessment, asset_name='PII server')
        self.assertEqual(item.likelihood_score, 6)
        self.assertEqual(item.risk_score, 30)
        self.assertEqual(item.risk_category, 'High')
        
        self.assertEqual(item.residual_likelihood_score, 2)
        self.assertEqual(item.residual_risk_score, 4)
        self.assertEqual(item.residual_risk_category, 'Low')
        
        # Verify treatment plan
        treatment = item.treatment
        self.assertEqual(treatment.status, 'In Progress')
        self.assertEqual(treatment.owner, 'SysAdmin')
        self.assertEqual(treatment.target_date, date(2026, 8, 1))
        
        # Verify detail page displays risk item and posture score (30)
        detail_url = reverse('assessment_detail', kwargs={'assessment_id': assessment.id})
        response = self.http_client.get(detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'PII server')
        self.assertContains(response, 'Hardware Failure')
        self.assertContains(response, 'High (30)')
        self.assertContains(response, 'Low (4)')


from evidence.models import EvidenceDocument

class DynamicAssessmentBuilderTestCase(TestCase):
    def setUp(self):
        self.http_client = HttpClient()
        
        # Create user
        self.user = User.objects.create_user(
            username='tester2@riskpilot.local', 
            email='tester2@riskpilot.local', 
            password='password123'
        )
        
        # Create tenant
        self.tenant = Tenant.objects.create(name='Dynamic Test Corp', domain='dynacorp')
        
        # Link user to tenant
        UserTenantMembership.objects.create(user=self.user, tenant=self.tenant, role='admin')
        
        # Create client
        self.client_org = Client.objects.create(tenant=self.tenant, name='Client Corp')
        
        # Create clean evidence document for testing
        self.evidence_doc = EvidenceDocument.objects.create(
            tenant=self.tenant,
            name="Backup Policy.pdf",
            created_by=self.user
        )

    def test_template_crud_cloning_and_versioning(self):
        self.http_client.force_login(self.user)
        
        # 1. Create template with range
        create_url = reverse('template_create')
        response = self.http_client.post(create_url, {
            'name': 'GDPR Self Assessment',
            'description': 'General Data Protection Regulations audit',
            'range_label': ['Non-Compliant', 'Compliant'],
            'range_min': ['0.0', '15.0'],
            'range_max': ['14.9', '30.0'],
            'range_color': ['danger', 'success']
        })
        self.assertEqual(response.status_code, 302)
        
        tpl = AssessmentTemplate.objects.filter(tenant=self.tenant, name='GDPR Self Assessment').first()
        self.assertIsNotNone(tpl)
        self.assertEqual(tpl.state, 'Draft')
        self.assertEqual(tpl.version, 1)
        self.assertEqual(tpl.scoring_ranges.count(), 2)
        
        # 2. Builder actions - Add Section
        builder_url = reverse('template_builder', kwargs={'template_id': tpl.id})
        response = self.http_client.post(builder_url, {
            'action': 'add_section',
            'name': 'Data Governance',
            'description': 'Security of processing data',
            'order': '1'
        })
        self.assertEqual(response.status_code, 302)
        sec = TemplateSection.objects.filter(template=tpl, name='Data Governance').first()
        self.assertIsNotNone(sec)
        
        # 3. Builder actions - Add Dropdown Question with choices
        response = self.http_client.post(builder_url, {
            'action': 'add_question',
            'section_id': sec.id,
            'text': 'Do you have a designated DPO?',
            'question_type': 'Dropdown',
            'is_required': '1',
            'order': '1',
            'help_text': 'Data Protection Officer requirement',
            'choices_raw': 'Yes|15.0\nNo|0.0'
        })
        self.assertEqual(response.status_code, 302)
        q1 = TemplateQuestion.objects.filter(section=sec, text='Do you have a designated DPO?').first()
        self.assertIsNotNone(q1)
        self.assertEqual(q1.choices.count(), 2)
        self.assertEqual(q1.choices.filter(text='Yes').first().score, 15.0)

        # 4. Builder actions - Add Evidence Question
        response = self.http_client.post(builder_url, {
            'action': 'add_question',
            'section_id': sec.id,
            'text': 'Attach DPO appointment letter',
            'question_type': 'Evidence',
            'is_required': '1',
            'order': '2'
        })
        self.assertEqual(response.status_code, 302)
        q2 = TemplateQuestion.objects.filter(section=sec, text='Attach DPO appointment letter').first()
        self.assertIsNotNone(q2)
        
        # 5. Publish Template
        publish_url = reverse('template_publish', kwargs={'template_id': tpl.id})
        response = self.http_client.post(publish_url)
        self.assertEqual(response.status_code, 302)
        tpl.refresh_from_db()
        self.assertEqual(tpl.state, 'Published')
        
        # 6. Create Version of Published Template
        version_url = reverse('template_create_version', kwargs={'template_id': tpl.id})
        response = self.http_client.post(version_url)
        self.assertEqual(response.status_code, 302)
        new_tpl = AssessmentTemplate.objects.filter(tenant=self.tenant, name='GDPR Self Assessment', version=2).first()
        self.assertIsNotNone(new_tpl)
        self.assertEqual(new_tpl.state, 'Draft')
        self.assertEqual(new_tpl.sections.count(), 1)
        self.assertEqual(new_tpl.sections.first().questions.count(), 2)
        
        # 7. Clone Template
        clone_url = reverse('template_clone', kwargs={'template_id': tpl.id})
        response = self.http_client.post(clone_url)
        self.assertEqual(response.status_code, 302)
        cloned = AssessmentTemplate.objects.filter(tenant=self.tenant, name='Clone of GDPR Self Assessment').first()
        self.assertIsNotNone(cloned)
        self.assertEqual(cloned.version, 1)
        self.assertEqual(cloned.state, 'Draft')

    def test_assessment_run_and_scoring(self):
        self.http_client.force_login(self.user)
        
        # Create a published template
        tpl = AssessmentTemplate.objects.create(
            tenant=self.tenant,
            name='Supplier Assessment Template',
            state='Published',
            is_latest=True
        )
        TemplateScoringRange.objects.create(
            tenant=self.tenant,
            template=tpl,
            label='Low Compliance',
            min_score=0.0,
            max_score=9.9,
            color='danger'
        )
        TemplateScoringRange.objects.create(
            tenant=self.tenant,
            template=tpl,
            label='High Compliance',
            min_score=10.0,
            max_score=20.0,
            color='success'
        )
        
        sec = TemplateSection.objects.create(
            tenant=self.tenant,
            template=tpl,
            name='Section A',
            order=1
        )
        
        q_choice = TemplateQuestion.objects.create(
            tenant=self.tenant,
            section=sec,
            text='Q1 Choice',
            question_type='Dropdown',
            is_required=True,
            order=1
        )
        choice_yes = QuestionChoice.objects.create(
            question=q_choice,
            text='Yes',
            score=10.0,
            order=1
        )
        choice_no = QuestionChoice.objects.create(
            question=q_choice,
            text='No',
            score=0.0,
            order=2
        )
        
        q_evidence = TemplateQuestion.objects.create(
            tenant=self.tenant,
            section=sec,
            text='Q2 Evidence',
            question_type='Evidence',
            is_required=True,
            order=2
        )
        
        # Start assessment run
        create_ass_url = reverse('template_assessment_create')
        response = self.http_client.post(create_ass_url, {
            'name': 'Supplier Run A',
            'client': self.client_org.id,
            'template': tpl.id
        })
        self.assertEqual(response.status_code, 302)
        
        ass = TemplateAssessment.objects.filter(tenant=self.tenant, name='Supplier Run A').first()
        self.assertIsNotNone(ass)
        self.assertEqual(ass.status, 'Draft')
        
        # Fill Answers
        fill_url = reverse('template_assessment_fill', kwargs={'assessment_id': ass.id, 'section_id': sec.id})
        response = self.http_client.post(fill_url, {
            'action': 'save',
            f'answer_{q_choice.id}': choice_yes.id,
            f'answer_{q_evidence.id}': [self.evidence_doc.id]
        })
        self.assertEqual(response.status_code, 302)
        
        # Verify answers in database
        ans_choice = TemplateAnswer.objects.filter(assessment=ass, question=q_choice).first()
        self.assertIsNotNone(ans_choice)
        self.assertEqual(ans_choice.selected_choices.first(), choice_yes)
        
        ans_ev = TemplateAnswer.objects.filter(assessment=ass, question=q_evidence).first()
        self.assertIsNotNone(ans_ev)
        self.assertEqual(ans_ev.attached_evidence.first(), self.evidence_doc)
        
        # Complete Assessment
        complete_url = reverse('template_assessment_complete', kwargs={'assessment_id': ass.id})
        response = self.http_client.post(complete_url)
        self.assertEqual(response.status_code, 302)
        
        # Verify total score & rating evaluation
        ass.refresh_from_db()
        self.assertEqual(ass.status, 'Completed')
        self.assertEqual(ass.total_score, 10.0)
        self.assertEqual(ass.compliance_rating, 'High Compliance')


class RoleBasedDashboardTests(TestCase):
    def setUp(self):
        self.http_client = HttpClient()
        
        # Tenants
        self.tenant = Tenant.objects.create(name='Dashboard Corp', domain='dashcorp')
        
        # Clients
        self.client_1 = Client.objects.create(tenant=self.tenant, name='Client One')
        self.client_2 = Client.objects.create(tenant=self.tenant, name='Client Two')
        
        # Users
        self.admin_user = User.objects.create_user(
            username='admin@riskpilot.local', email='admin@riskpilot.local', password='password123'
        )
        self.assessor_user_1 = User.objects.create_user(
            username='assessor1@riskpilot.local', email='assessor1@riskpilot.local', password='password123'
        )
        self.assessor_user_2 = User.objects.create_user(
            username='assessor2@riskpilot.local', email='assessor2@riskpilot.local', password='password123'
        )
        self.client_user = User.objects.create_user(
            username='client@riskpilot.local', email='client@riskpilot.local', password='password123'
        )
        
        # Link users to tenant & roles
        UserTenantMembership.objects.create(user=self.admin_user, tenant=self.tenant, role='admin')
        UserTenantMembership.objects.create(user=self.assessor_user_1, tenant=self.tenant, role='assessor')
        UserTenantMembership.objects.create(user=self.assessor_user_2, tenant=self.tenant, role='assessor')
        UserTenantMembership.objects.create(
            user=self.client_user, tenant=self.tenant, role='client', client=self.client_1
        )
        
        # Methodology & version
        self.methodology = AssessmentMethodology.objects.create(tenant=self.tenant, name='Dashboard Method')
        self.version = AssessmentMethodologyVersion.objects.create(
            tenant=self.tenant, methodology=self.methodology, version_number='1.0'
        )
        
        # Setup criteria
        self.freq = ThreatFrequencyCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Medium', score=2
        )
        self.prob = VulnerabilityProbabilityCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Medium', score=2
        )
        self.imp = ImpactCriteria.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Medium', score=2
        )
        for i in range(1, 7):
            LikelihoodCriteria.objects.create(
                tenant=self.tenant, methodology_version=self.version, score_value=i, label=f"L-Label-{i}"
            )
        self.cat_med = RiskCategory.objects.create(
            tenant=self.tenant, methodology_version=self.version, label='Medium', min_score=1, max_score=10
        )
        
        # Threat
        self.t_cat = ThreatCategory.objects.create(tenant=self.tenant, name='Security')
        self.threat = Threat.objects.create(tenant=self.tenant, category=self.t_cat, name='Data Leak')
        
        # Create Assessments
        self.ass_1 = Assessment.objects.create(
            tenant=self.tenant, client=self.client_1, methodology_version=self.version,
            name='Assessment Client 1', status='InProgress', assessor=self.assessor_user_1
        )
        self.ass_2 = Assessment.objects.create(
            tenant=self.tenant, client=self.client_2, methodology_version=self.version,
            name='Assessment Client 2', status='InProgress', assessor=self.assessor_user_2
        )
        
        # Risk Item
        self.risk_item = RiskItem.objects.create(
            tenant=self.tenant, assessment=self.ass_1, asset_name='Server 1',
            threat=self.threat, threat_frequency=self.freq, vulnerability_probability=self.prob, impact_severity=self.imp
        )

    def test_client_role_dashboard_lock(self):
        """
        Verify that client users are locked to the client dashboard
        and cannot request the executive or assessor dashboards.
        """
        self.http_client.force_login(self.client_user)
        
        # Try default dashboard access
        response = self.http_client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['dashboard_type'], 'client')
        
        # Try accessing executive dashboard via GET param
        response = self.http_client.get(reverse('dashboard') + '?dashboard_type=executive')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['dashboard_type'], 'client')
        
        # Try accessing assessor dashboard via GET param
        response = self.http_client.get(reverse('dashboard') + '?dashboard_type=assessor')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['dashboard_type'], 'client')

    def test_assessor_dashboard_scoping(self):
        """
        Verify that the assessor dashboard only shows assessments assigned to the logged-in assessor.
        """
        # Assessor 1
        self.http_client.force_login(self.assessor_user_1)
        response = self.http_client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['dashboard_type'], 'assessor')
        self.assertIn(self.ass_1, response.context['assigned_assessments'])
        self.assertNotIn(self.ass_2, response.context['assigned_assessments'])
        
        # Assessor 2
        self.http_client.force_login(self.assessor_user_2)
        response = self.http_client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['dashboard_type'], 'assessor')
        self.assertIn(self.ass_2, response.context['assigned_assessments'])
        self.assertNotIn(self.ass_1, response.context['assigned_assessments'])

    def test_executive_dashboard_filtering(self):
        """
        Verify that filtering by client restricts calculations to that client's assessments.
        """
        self.http_client.force_login(self.admin_user)
        
        # No filters
        response = self.http_client.get(reverse('dashboard') + '?dashboard_type=executive')
        self.assertEqual(response.status_code, 200)
        # Should include both assessments
        self.assertEqual(len(response.context['assessments']), 2)
        
        # Filter by Client 1
        response = self.http_client.get(reverse('dashboard') + f'?dashboard_type=executive&client={self.client_1.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['assessments']), 1)
        self.assertEqual(response.context['assessments'][0], self.ass_1)
        
        # Filter by Assessment 1
        response = self.http_client.get(reverse('dashboard') + f'?dashboard_type=executive&assessment={self.ass_1.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['assessments']), 1)
        self.assertEqual(response.context['assessments'][0], self.ass_1)

    def test_ai_suggestion_review_workflow(self):
        """
        Test applying and rejecting AI suggestions.
        """
        from ai_assist.models import AISuggestion
        
        # Create pending AI Suggestion
        suggestion = AISuggestion.objects.create(
            tenant=self.tenant,
            risk_item=self.risk_item,
            prompt='Mock prompt',
            suggestion_text='Implement MFA',
            status='Pending'
        )
        
        # Try to apply suggestion as client user: should get 403
        self.http_client.force_login(self.client_user)
        review_url = reverse('ai_suggestion_review', kwargs={'suggestion_id': suggestion.id})
        response = self.http_client.post(review_url, {'action': 'apply'})
        self.assertEqual(response.status_code, 403)
        
        # Apply suggestion as assessor
        self.http_client.force_login(self.assessor_user_1)
        response = self.http_client.post(review_url, {'action': 'apply'})
        self.assertEqual(response.status_code, 200)
        
        suggestion.refresh_from_db()
        self.assertEqual(suggestion.status, 'Applied')
        
        # Reject suggestion
        suggestion.status = 'Pending'
        suggestion.save()
        response = self.http_client.post(review_url, {'action': 'reject'})
        self.assertEqual(response.status_code, 200)
        suggestion.refresh_from_db()
        self.assertEqual(suggestion.status, 'Rejected')
