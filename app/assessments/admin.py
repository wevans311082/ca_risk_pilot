from django.contrib import admin
from .models import (
    AssessmentMethodology, AssessmentMethodologyVersion,
    ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, LikelihoodCriteria,
    ImpactCriteria, RiskCategory, ThreatCategory, Threat, Assessment, RiskItem, RiskTreatment,
    AssessmentTemplate, TemplateSection, TemplateQuestion, QuestionChoice,
    TemplateScoringRange, TemplateAssessment, TemplateAnswer,
    CentralRisk, RiskHistory
)

# Inlines for versioning configuration
class AssessmentMethodologyVersionInline(admin.TabularInline):
    model = AssessmentMethodologyVersion
    extra = 1
    show_change_link = True


# Inlines for scoring lookup criteria
class ThreatFrequencyCriteriaInline(admin.TabularInline):
    model = ThreatFrequencyCriteria
    extra = 3


class VulnerabilityProbabilityCriteriaInline(admin.TabularInline):
    model = VulnerabilityProbabilityCriteria
    extra = 3


class LikelihoodCriteriaInline(admin.TabularInline):
    model = LikelihoodCriteria
    extra = 5


class ImpactCriteriaInline(admin.TabularInline):
    model = ImpactCriteria
    extra = 5


class RiskCategoryInline(admin.TabularInline):
    model = RiskCategory
    extra = 3


# Inlines for Assessment and Risk Items
class RiskItemInline(admin.StackedInline):
    model = RiskItem
    extra = 1
    show_change_link = True


class RiskTreatmentInline(admin.StackedInline):
    model = RiskTreatment
    extra = 1


# Admin registrations
@admin.register(AssessmentMethodology)
class AssessmentMethodologyAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'is_active', 'is_deleted', 'created_at')
    list_filter = ('tenant', 'is_active', 'is_deleted')
    search_fields = ('name', 'description')
    inlines = [AssessmentMethodologyVersionInline]


@admin.register(AssessmentMethodologyVersion)
class AssessmentMethodologyVersionAdmin(admin.ModelAdmin):
    list_display = ('methodology', 'version_number', 'tenant', 'is_active', 'is_deleted')
    list_filter = ('tenant', 'is_active', 'is_deleted')
    search_fields = ('methodology__name', 'version_number')
    inlines = [
        ThreatFrequencyCriteriaInline,
        VulnerabilityProbabilityCriteriaInline,
        LikelihoodCriteriaInline,
        ImpactCriteriaInline,
        RiskCategoryInline
    ]


@admin.register(ThreatCategory)
class ThreatCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'is_deleted')
    list_filter = ('tenant', 'is_deleted')
    search_fields = ('name',)


@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'tenant', 'is_deleted')
    list_filter = ('tenant', 'category', 'is_deleted')
    search_fields = ('name', 'category__name')


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'client', 'assessor', 'methodology_version', 'tenant', 'status', 'is_deleted')
    list_filter = ('tenant', 'status', 'assessor', 'is_deleted')
    search_fields = ('name', 'client__name')
    inlines = [RiskItemInline]


@admin.register(RiskItem)
class RiskItemAdmin(admin.ModelAdmin):
    list_display = ('asset_name', 'assessment', 'threat', 'tenant', 'is_deleted')
    list_filter = ('tenant', 'is_deleted')
    search_fields = ('asset_name', 'vulnerability')
    inlines = [RiskTreatmentInline]


@admin.register(CentralRisk)
class CentralRiskAdmin(admin.ModelAdmin):
    list_display = ('asset_name', 'client', 'owner', 'status', 'tenant')
    list_filter = ('tenant', 'status')
    search_fields = ('asset_name', 'vulnerability')


@admin.register(RiskHistory)
class RiskHistoryAdmin(admin.ModelAdmin):
    list_display = ('risk', 'changed_by', 'action', 'changed_at', 'tenant')
    list_filter = ('tenant', 'action')


# General admin registration for lookups (for easier editing/viewing)
@admin.register(ThreatFrequencyCriteria)
class ThreatFrequencyCriteriaAdmin(admin.ModelAdmin):
    list_display = ('label', 'score', 'methodology_version', 'tenant')

@admin.register(VulnerabilityProbabilityCriteria)
class VulnerabilityProbabilityCriteriaAdmin(admin.ModelAdmin):
    list_display = ('label', 'score', 'methodology_version', 'tenant')

@admin.register(LikelihoodCriteria)
class LikelihoodCriteriaAdmin(admin.ModelAdmin):
    list_display = ('score_value', 'label', 'methodology_version', 'tenant')

@admin.register(ImpactCriteria)
class ImpactCriteriaAdmin(admin.ModelAdmin):
    list_display = ('label', 'score', 'financial_impact_range', 'methodology_version', 'tenant')

@admin.register(RiskCategory)
class RiskCategoryAdmin(admin.ModelAdmin):
    list_display = ('label', 'min_score', 'max_score', 'methodology_version', 'tenant')

@admin.register(RiskTreatment)
class RiskTreatmentAdmin(admin.ModelAdmin):
    list_display = ('risk_item', 'status', 'owner', 'target_date', 'tenant')
    list_filter = ('tenant', 'status')


class TemplateSectionInline(admin.TabularInline):
    model = TemplateSection
    extra = 1
    show_change_link = True


class TemplateScoringRangeInline(admin.TabularInline):
    model = TemplateScoringRange
    extra = 1


class QuestionChoiceInline(admin.TabularInline):
    model = QuestionChoice
    extra = 3


class TemplateAnswerInline(admin.TabularInline):
    model = TemplateAnswer
    extra = 0
    readonly_fields = ('question', 'text_value', 'selected_choices', 'attached_evidence')
    can_delete = False


@admin.register(AssessmentTemplate)
class AssessmentTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'version', 'state', 'is_latest', 'tenant', 'is_deleted')
    list_filter = ('tenant', 'state', 'is_latest', 'is_deleted')
    search_fields = ('name', 'description')
    inlines = [TemplateSectionInline, TemplateScoringRangeInline]


@admin.register(TemplateSection)
class TemplateSectionAdmin(admin.ModelAdmin):
    list_display = ('name', 'template', 'order', 'tenant', 'is_deleted')
    list_filter = ('tenant', 'is_deleted')
    search_fields = ('name', 'template__name')


@admin.register(TemplateQuestion)
class TemplateQuestionAdmin(admin.ModelAdmin):
    list_display = ('text', 'section', 'question_type', 'is_required', 'order', 'tenant', 'is_deleted')
    list_filter = ('tenant', 'question_type', 'is_required', 'is_deleted')
    search_fields = ('text', 'section__name')
    inlines = [QuestionChoiceInline]


@admin.register(TemplateScoringRange)
class TemplateScoringRangeAdmin(admin.ModelAdmin):
    list_display = ('label', 'template', 'min_score', 'max_score', 'color', 'tenant')
    list_filter = ('tenant',)


@admin.register(TemplateAssessment)
class TemplateAssessmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'client', 'assessor', 'template', 'status', 'total_score', 'compliance_rating', 'tenant', 'is_deleted')
    list_filter = ('tenant', 'status', 'assessor', 'is_deleted')
    search_fields = ('name', 'client__name', 'template__name')
    inlines = [TemplateAnswerInline]
