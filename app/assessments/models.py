from django.db import models
from tenants.models import TenantOwnedSoftDeleteModel

class AssessmentMethodology(TenantOwnedSoftDeleteModel):
    """
    Methodology containing scoring parameters and threat libraries.
    """
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'name']),
        ]

    def __str__(self):
        return self.name


class AssessmentMethodologyVersion(TenantOwnedSoftDeleteModel):
    """
    A version of an AssessmentMethodology to preserve historical calculations.
    """
    methodology = models.ForeignKey(AssessmentMethodology, on_delete=models.CASCADE, related_name='versions')
    version_number = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'methodology', 'version_number']),
        ]
        unique_together = ('methodology', 'version_number')

    def __str__(self):
        return f"{self.methodology.name} (v{self.version_number})"


class ThreatFrequencyCriteria(TenantOwnedSoftDeleteModel):
    """
    Database-driven threat frequency scoring values.
    """
    methodology_version = models.ForeignKey(AssessmentMethodologyVersion, on_delete=models.CASCADE, related_name='frequency_criteria')
    label = models.CharField(max_length=255)
    score = models.IntegerField(help_text="Frequency score value (e.g. 1, 2, 3)")

    class Meta:
        ordering = ['score']

    def __str__(self):
        return f"{self.label} (Score: {self.score})"


class VulnerabilityProbabilityCriteria(TenantOwnedSoftDeleteModel):
    """
    Database-driven vulnerability probability scoring values.
    """
    methodology_version = models.ForeignKey(AssessmentMethodologyVersion, on_delete=models.CASCADE, related_name='probability_criteria')
    label = models.CharField(max_length=255)
    score = models.IntegerField(help_text="Probability score value (e.g. 1, 2, 3)")

    class Meta:
        ordering = ['score']

    def __str__(self):
        return f"{self.label} (Score: {self.score})"


class LikelihoodCriteria(TenantOwnedSoftDeleteModel):
    """
    Configurable lookup mapping combined scores (1-6) to Likelihood labels.
    """
    methodology_version = models.ForeignKey(AssessmentMethodologyVersion, on_delete=models.CASCADE, related_name='likelihood_criteria')
    score_value = models.IntegerField(help_text="Likelihood sum value (e.g. 1, 2, 3, 4, 5, 6)")
    label = models.CharField(max_length=255, help_text="e.g. Very Low, Low, Medium, High, Very High")

    class Meta:
        ordering = ['score_value']
        unique_together = ('methodology_version', 'score_value')

    def __str__(self):
        return f"{self.score_value} = {self.label}"


class ImpactCriteria(TenantOwnedSoftDeleteModel):
    """
    Database-driven impact severity scoring values with descriptions and financial ranges.
    """
    methodology_version = models.ForeignKey(AssessmentMethodologyVersion, on_delete=models.CASCADE, related_name='impact_criteria')
    label = models.CharField(max_length=255, help_text="e.g. Minor, Moderate, Major")
    score = models.IntegerField(help_text="Severity score value (e.g. 1, 2, 3, 4, 5)")
    description = models.TextField(blank=True)
    financial_impact_range = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ['score']

    def __str__(self):
        return f"{self.label} ({self.score}) - {self.financial_impact_range}"


class RiskCategory(TenantOwnedSoftDeleteModel):
    """
    Database-driven risk categorization thresholds (e.g. score < 5 = Low).
    """
    methodology_version = models.ForeignKey(AssessmentMethodologyVersion, on_delete=models.CASCADE, related_name='risk_categories')
    label = models.CharField(max_length=255, help_text="e.g. Low, Medium, High")
    min_score = models.IntegerField()
    max_score = models.IntegerField()

    class Meta:
        ordering = ['min_score']

    def __str__(self):
        return f"{self.label} ({self.min_score}-{self.max_score})"


class ThreatCategory(TenantOwnedSoftDeleteModel):
    """
    Threat library categories (e.g. Technical Failures, Unauthorised Actions).
    """
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class Threat(TenantOwnedSoftDeleteModel):
    """
    Configurable threats catalog.
    """
    category = models.ForeignKey(ThreatCategory, on_delete=models.CASCADE, related_name='threats')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)

    def __str__(self):
        return f"{self.category.name} - {self.name}"


class Assessment(TenantOwnedSoftDeleteModel):
    """
    A specific evaluation instance run for a Client using a versioned Methodology.
    """
    STATUS_CHOICES = [
        ('Draft', 'Draft'),
        ('InProgress', 'In Progress'),
        ('UnderReview', 'Under Review'),
        ('Completed', 'Completed'),
        ('Archived', 'Archived'),
    ]

    client = models.ForeignKey('tenants.Client', on_delete=models.CASCADE, related_name='assessments')
    methodology_version = models.ForeignKey(AssessmentMethodologyVersion, on_delete=models.CASCADE, related_name='assessments')
    assessor = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_assessments')
    
    name = models.CharField(max_length=255)
    change_request = models.TextField(blank=True, help_text="Associated Change Request context.")
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Draft')
    
    # Core main asset default fields (as per Assessment Structure requirements)
    asset = models.CharField(max_length=255, blank=True)
    location = models.CharField(max_length=255, blank=True)
    owner = models.CharField(max_length=255, blank=True)
    threat = models.ForeignKey(Threat, on_delete=models.SET_NULL, null=True, blank=True, related_name='base_assessments')
    vulnerability = models.TextField(blank=True)
    existing_controls = models.TextField(blank=True)
    business_process_impact = models.TextField(blank=True)
    
    confidentiality_affected = models.BooleanField(default=False)
    integrity_affected = models.BooleanField(default=False)
    availability_affected = models.BooleanField(default=False)

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'client', 'status']),
        ]

    def __str__(self):
        return self.name


class CentralRisk(TenantOwnedSoftDeleteModel):
    """
    A Central Risk that can exist independently of assessments, with lifecycle, review, and acceptance states.
    """
    STATUS_CHOICES = [
        ('Draft', 'Draft'),
        ('Active', 'Active'),
        ('Under Review', 'Under Review'),
        ('Mitigated', 'Mitigated'),
        ('Accepted', 'Accepted'),
        ('Archived', 'Archived'),
    ]

    ACCEPTANCE_STATUS_CHOICES = [
        ('None', 'None'),
        ('Pending', 'Pending'),
        ('Accepted', 'Accepted'),
        ('Expired', 'Expired'),
        ('Rejected', 'Rejected'),
    ]

    client = models.ForeignKey('tenants.Client', on_delete=models.CASCADE, related_name='central_risks')
    owner = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_risks')
    
    asset_name = models.CharField(max_length=255)
    asset_location = models.CharField(max_length=255, blank=True)
    asset_owner = models.CharField(max_length=255, blank=True)
    
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE, related_name='central_risks')
    vulnerability = models.TextField()
    existing_controls = models.TextField(blank=True)
    
    confidentiality_affected = models.BooleanField(default=False)
    integrity_affected = models.BooleanField(default=False)
    availability_affected = models.BooleanField(default=False)
    
    # Inherent Risk Scoring
    threat_frequency = models.ForeignKey(ThreatFrequencyCriteria, on_delete=models.PROTECT, related_name='central_risks')
    vulnerability_probability = models.ForeignKey(VulnerabilityProbabilityCriteria, on_delete=models.PROTECT, related_name='central_risks')
    impact_severity = models.ForeignKey(ImpactCriteria, on_delete=models.PROTECT, related_name='central_risks')
    
    # Treatment & Residual Scoring
    proposed_controls = models.TextField(blank=True)
    additional_mitigations = models.TextField(blank=True)
    
    residual_threat_frequency = models.ForeignKey(ThreatFrequencyCriteria, on_delete=models.PROTECT, null=True, blank=True, related_name='residual_central_risks')
    residual_vulnerability_probability = models.ForeignKey(VulnerabilityProbabilityCriteria, on_delete=models.PROTECT, null=True, blank=True, related_name='residual_central_risks')
    residual_impact_severity = models.ForeignKey(ImpactCriteria, on_delete=models.PROTECT, null=True, blank=True, related_name='residual_central_risks')

    # Lifecycle & Review Workflow
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Draft')
    review_date = models.DateField(null=True, blank=True)
    last_reviewed_at = models.DateTimeField(null=True, blank=True)

    # Risk Acceptance
    acceptance_status = models.CharField(max_length=50, choices=ACCEPTANCE_STATUS_CHOICES, default='None')
    accepted_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='accepted_risks')
    acceptance_rationale = models.TextField(blank=True)
    acceptance_date = models.DateField(null=True, blank=True)
    acceptance_expiry = models.DateField(null=True, blank=True)

    def get_methodology_version(self):
        return AssessmentMethodologyVersion.objects.filter(tenant=self.tenant, is_active=True).first()

    def check_acceptance_expiry(self):
        """
        Check if the risk acceptance has expired. If so, update status to 'Under Review' and acceptance_status to 'Expired'.
        """
        from django.utils import timezone
        if self.status == 'Accepted' and self.acceptance_expiry and self.acceptance_expiry < timezone.now().date():
            self.status = 'Under Review'
            self.acceptance_status = 'Expired'
            self.save()
            
            RiskHistory.objects.create(
                tenant=self.tenant,
                risk=self,
                changed_by=None,
                action="Expiry",
                description="Risk acceptance expired automatically.",
                snapshot={
                    'status': self.status,
                    'acceptance_status': self.acceptance_status,
                }
            )
            return True
        return False

    @property
    def likelihood_score(self):
        return self.threat_frequency.score + self.vulnerability_probability.score

    @property
    def likelihood_label(self):
        version = self.get_methodology_version()
        if version:
            crit = LikelihoodCriteria.objects.filter(methodology_version=version, score_value=self.likelihood_score).first()
            return crit.label if crit else "N/A"
        return "N/A"

    @property
    def risk_score(self):
        return self.likelihood_score * self.impact_severity.score

    @property
    def risk_category(self):
        version = self.get_methodology_version()
        if version:
            score = self.risk_score
            cat = RiskCategory.objects.filter(methodology_version=version, min_score__lte=score, max_score__gte=score).first()
            return cat.label if cat else "N/A"
        return "N/A"

    @property
    def residual_likelihood_score(self):
        if self.residual_threat_frequency and self.residual_vulnerability_probability:
            return self.residual_threat_frequency.score + self.residual_vulnerability_probability.score
        return None

    @property
    def residual_likelihood_label(self):
        score = self.residual_likelihood_score
        if score is not None:
            version = self.get_methodology_version()
            if version:
                crit = LikelihoodCriteria.objects.filter(methodology_version=version, score_value=score).first()
                return crit.label if crit else "N/A"
        return "N/A"

    @property
    def residual_risk_score(self):
        lik = self.residual_likelihood_score
        if lik is not None and self.residual_impact_severity:
            return lik * self.residual_impact_severity.score
        return None

    @property
    def residual_risk_category(self):
        score = self.residual_risk_score
        if score is not None:
            version = self.get_methodology_version()
            if version:
                cat = RiskCategory.objects.filter(methodology_version=version, min_score__lte=score, max_score__gte=score).first()
                return cat.label if cat else "N/A"
        return "N/A"

    def __str__(self):
        return f"{self.asset_name} - {self.threat.name} (Status: {self.status})"


class RiskHistory(TenantOwnedSoftDeleteModel):
    """
    Ledger recording modifications, reviews, and acceptances on Central Risks.
    """
    risk = models.ForeignKey(CentralRisk, on_delete=models.CASCADE, related_name='history_entries')
    changed_by = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True)
    changed_at = models.DateTimeField(auto_now_add=True)
    action = models.CharField(max_length=100)
    description = models.TextField()
    snapshot = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"History ({self.action}) on Risk {self.risk.id} at {self.changed_at}"


class RiskItem(TenantOwnedSoftDeleteModel):
    """
    Individual risk items recorded under a specific Assessment.
    """
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='risk_items')
    central_risk = models.ForeignKey(CentralRisk, on_delete=models.SET_NULL, null=True, blank=True, related_name='assessment_items')
    
    asset_name = models.CharField(max_length=255)
    asset_location = models.CharField(max_length=255)
    asset_owner = models.CharField(max_length=255)
    
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE, related_name='risk_items')
    vulnerability = models.TextField()
    existing_controls = models.TextField()
    
    # CIA assessment (supports multiple checkmark selections)
    confidentiality_affected = models.BooleanField(default=False)
    integrity_affected = models.BooleanField(default=False)
    availability_affected = models.BooleanField(default=False)
    
    # Inherent Risk Scoring
    threat_frequency = models.ForeignKey(ThreatFrequencyCriteria, on_delete=models.PROTECT, related_name='risk_items')
    vulnerability_probability = models.ForeignKey(VulnerabilityProbabilityCriteria, on_delete=models.PROTECT, related_name='risk_items')
    impact_severity = models.ForeignKey(ImpactCriteria, on_delete=models.PROTECT, related_name='risk_items')
    
    # Treatment & Residual Scoring
    proposed_controls = models.TextField(blank=True)
    additional_mitigations = models.TextField(blank=True)
    
    residual_threat_frequency = models.ForeignKey(ThreatFrequencyCriteria, on_delete=models.PROTECT, null=True, blank=True, related_name='residual_risk_items')
    residual_vulnerability_probability = models.ForeignKey(VulnerabilityProbabilityCriteria, on_delete=models.PROTECT, null=True, blank=True, related_name='residual_risk_items')
    residual_impact_severity = models.ForeignKey(ImpactCriteria, on_delete=models.PROTECT, null=True, blank=True, related_name='residual_risk_items')

    @property
    def likelihood_score(self):
        return self.threat_frequency.score + self.vulnerability_probability.score

    @property
    def likelihood_label(self):
        version = self.assessment.methodology_version
        crit = LikelihoodCriteria.objects.filter(methodology_version=version, score_value=self.likelihood_score).first()
        return crit.label if crit else "N/A"

    @property
    def risk_score(self):
        return self.likelihood_score * self.impact_severity.score

    @property
    def risk_category(self):
        version = self.assessment.methodology_version
        score = self.risk_score
        cat = RiskCategory.objects.filter(methodology_version=version, min_score__lte=score, max_score__gte=score).first()
        return cat.label if cat else "N/A"

    @property
    def residual_likelihood_score(self):
        if self.residual_threat_frequency and self.residual_vulnerability_probability:
            return self.residual_threat_frequency.score + self.residual_vulnerability_probability.score
        return None

    @property
    def residual_likelihood_label(self):
        score = self.residual_likelihood_score
        if score is not None:
            version = self.assessment.methodology_version
            crit = LikelihoodCriteria.objects.filter(methodology_version=version, score_value=score).first()
            return crit.label if crit else "N/A"
        return "N/A"

    @property
    def residual_risk_score(self):
        lik = self.residual_likelihood_score
        if lik is not None and self.residual_impact_severity:
            return lik * self.residual_impact_severity.score
        return None

    @property
    def residual_risk_category(self):
        score = self.residual_risk_score
        if score is not None:
            version = self.assessment.methodology_version
            cat = RiskCategory.objects.filter(methodology_version=version, min_score__lte=score, max_score__gte=score).first()
            return cat.label if cat else "N/A"
        return "N/A"

    def sync_to_central_risk(self, user):
        if not self.central_risk:
            return
        cr = self.central_risk
        cr.asset_name = self.asset_name
        cr.asset_location = self.asset_location
        cr.asset_owner = self.asset_owner
        cr.threat = self.threat
        cr.vulnerability = self.vulnerability
        cr.existing_controls = self.existing_controls
        cr.confidentiality_affected = self.confidentiality_affected
        cr.integrity_affected = self.integrity_affected
        cr.availability_affected = self.availability_affected
        cr.threat_frequency = self.threat_frequency
        cr.vulnerability_probability = self.vulnerability_probability
        cr.impact_severity = self.impact_severity
        cr.proposed_controls = self.proposed_controls
        cr.additional_mitigations = self.additional_mitigations
        cr.residual_threat_frequency = self.residual_threat_frequency
        cr.residual_vulnerability_probability = self.residual_vulnerability_probability
        cr.residual_impact_severity = self.residual_impact_severity
        if cr.status == 'Draft':
            cr.status = 'Active'
        cr.save()
        
        # Log snapshot to RiskHistory
        from .views_central_risk import get_snapshot
        RiskHistory.objects.create(
            tenant=cr.tenant,
            risk=cr,
            changed_by=user,
            action="Update",
            description=f"Risk updated via sync from assessment '{self.assessment.name}'.",
            snapshot=get_snapshot(cr)
        )

    def __str__(self):
        return f"{self.asset_name} - {self.threat.name} (Inherent: {self.risk_score})"


class RiskTreatment(TenantOwnedSoftDeleteModel):
    """
    Treatment plan actions tracked for specific RiskItems.
    """
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Accepted Risk', 'Accepted Risk'),
        ('Mitigated', 'Mitigated'),
        ('Closed', 'Closed'),
    ]

    risk_item = models.OneToOneField(RiskItem, on_delete=models.CASCADE, related_name='treatment')
    action = models.TextField(blank=True)
    owner = models.CharField(max_length=255, blank=True)
    target_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Open')
    completion_notes = models.TextField(blank=True)

    def __str__(self):
        return f"Treatment ({self.status}) for RiskItem {self.risk_item.id}"


class AssessmentTemplate(TenantOwnedSoftDeleteModel):
    """
    Logical assessment template definition (e.g. Supplier Assessment).
    Supports Draft/Published states and version history.
    """
    STATE_CHOICES = [
        ('Draft', 'Draft'),
        ('Published', 'Published'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    version = models.PositiveIntegerField(default=1)
    state = models.CharField(max_length=50, choices=STATE_CHOICES, default='Draft')
    is_latest = models.BooleanField(default=True)
    parent_template = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='versions')

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'name', 'is_latest']),
        ]

    def __str__(self):
        return f"{self.name} (v{self.version}) [{self.state}]"


class TemplateSection(TenantOwnedSoftDeleteModel):
    """
    Sections within an AssessmentTemplate to group questions logically.
    """
    template = models.ForeignKey(AssessmentTemplate, on_delete=models.CASCADE, related_name='sections')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['order']
        indexes = [
            models.Index(fields=['template', 'order']),
        ]

    def __str__(self):
        return f"{self.template.name} - {self.name}"


class TemplateQuestion(TenantOwnedSoftDeleteModel):
    """
    Individual question config. Answers are mapped dynamically.
    """
    TYPE_CHOICES = [
        ('Text', 'Short Text'),
        ('LongText', 'Long Text / TextArea'),
        ('Dropdown', 'Single-Select Dropdown'),
        ('MultiSelect', 'Multi-Select Checkboxes'),
        ('Radio', 'Radio Buttons'),
        ('Date', 'Date Selector'),
        ('Numeric', 'Numeric Input'),
        ('Evidence', 'Evidence File Upload Required'),
    ]

    section = models.ForeignKey(TemplateSection, on_delete=models.CASCADE, related_name='questions')
    text = models.CharField(max_length=500)
    help_text = models.TextField(blank=True)
    guidance_notes = models.TextField(blank=True)
    question_type = models.CharField(max_length=50, choices=TYPE_CHOICES, default='Text')
    is_required = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['order']
        indexes = [
            models.Index(fields=['section', 'order']),
        ]

    def __str__(self):
        return f"{self.section.name} -> {self.text[:50]}"


class QuestionChoice(models.Model):
    """
    Option values for Dropdown, Radio, and MultiSelect questions with weight scores.
    """
    question = models.ForeignKey(TemplateQuestion, on_delete=models.CASCADE, related_name='choices')
    text = models.CharField(max_length=255)
    score = models.FloatField(default=0.0, help_text="Compliance weight score for this choice selection.")
    order = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['order']
        indexes = [
            models.Index(fields=['question', 'order']),
        ]

    def __str__(self):
        return f"{self.text} (Score: {self.score})"


class TemplateScoringRange(TenantOwnedSoftDeleteModel):
    """
    Range definitions to map final total scoring to compliance labels.
    """
    template = models.ForeignKey(AssessmentTemplate, on_delete=models.CASCADE, related_name='scoring_ranges')
    label = models.CharField(max_length=100, help_text="e.g. Highly Compliant, Unacceptable Risk")
    min_score = models.FloatField()
    max_score = models.FloatField()
    color = models.CharField(max_length=50, default='success', help_text="Bootstrap contextual class name (success, warning, danger).")

    class Meta:
        ordering = ['min_score']

    def __str__(self):
        return f"{self.label} ({self.min_score} - {self.max_score})"


class TemplateAssessment(TenantOwnedSoftDeleteModel):
    """
    An instance run of a dynamically built AssessmentTemplate.
    """
    STATUS_CHOICES = [
        ('Draft', 'Draft'),
        ('InProgress', 'In Progress'),
        ('UnderReview', 'Under Review'),
        ('Completed', 'Completed'),
    ]

    client = models.ForeignKey('tenants.Client', on_delete=models.CASCADE, related_name='template_assessments')
    template = models.ForeignKey(AssessmentTemplate, on_delete=models.CASCADE, related_name='assessments')
    assessor = models.ForeignKey('accounts.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_template_assessments')
    name = models.CharField(max_length=255)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Draft')
    total_score = models.FloatField(null=True, blank=True)
    compliance_rating = models.CharField(max_length=100, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['tenant', 'client', 'status']),
        ]

    def __str__(self):
        return f"{self.name} ({self.template.name})"


class TemplateAnswer(models.Model):
    """
    Assessment run dynamic responses.
    """
    assessment = models.ForeignKey(TemplateAssessment, on_delete=models.CASCADE, related_name='answers')
    question = models.ForeignKey(TemplateQuestion, on_delete=models.CASCADE)
    text_value = models.TextField(blank=True) # Text, LongText, Date, Numeric values
    selected_choices = models.ManyToManyField(QuestionChoice, blank=True)
    attached_evidence = models.ManyToManyField('evidence.EvidenceDocument', blank=True)

    class Meta:
        unique_together = ('assessment', 'question')

    def __str__(self):
        return f"{self.assessment.name} -> {self.question.text[:30]}"

