from django.core.management.base import BaseCommand, CommandError

from assessments.seed_templates import get_seed_templates
from assessments.models import (
    AssessmentMethodology,
    AssessmentMethodologyVersion,
    ImpactCriteria,
    LikelihoodCriteria,
    QuestionChoice,
    RiskCategory,
    TemplateQuestion,
    TemplateScoringRange,
    TemplateSection,
    AssessmentTemplate,
    Threat,
    ThreatCategory,
    ThreatFrequencyCriteria,
    VulnerabilityProbabilityCriteria,
)
from tenants.isolation import clear_current_tenant, set_current_tenant
from tenants.models import Tenant


THREAT_LIBRARY = {
    "Physical Damage": [
        "Fire", "Water Damage", "Pollution", "Major Accident",
        "Destruction of Equipment", "Dust Corrosion Freezing",
    ],
    "Natural Events": [
        "Climatic Phenomenon", "Seismic Phenomenon", "Volcanic Phenomenon", "Flood", "Pandemic",
    ],
    "Loss of Essential Services": [
        "Failure of Air Conditioning", "Failure of Power Supply", "Failure of Telecommunications", "Fuel Shortage",
    ],
    "Technical Failures": [
        "Hardware Failure", "Software Failure", "Network Failure", "Data Corruption",
    ],
    "Unauthorised Actions": [
        "Sharing of Access Privileges", "Malicious Insider Activity", "Privilege Abuse", "Unauthorised Access",
    ],
    "Compromise of Information": [
        "Loss of Data", "Disclosure of Data", "Theft of Data", "Incorrect Modification",
    ],
    "Compromise of Functions": [
        "Service Interruption", "Supplier Failure", "Cloud Service Outage",
    ],
}


TEMPLATES = [
    {
        "name": "Cyber Risk Assessment",
        "description": "Standard assessment of cyber security posture including firewall, backups, and access control.",
        "sections": [
            {
                "name": "Network Security",
                "order": 1,
                "questions": [
                    {
                        "text": "Are firewalls deployed at all network boundaries?",
                        "question_type": "Dropdown",
                        "order": 1,
                        "help_text": "Check all internet-facing entry points.",
                        "guidance_notes": "Firewalls should block inbound traffic by default.",
                        "choices": [("Yes", 10.0), ("Partial", 5.0), ("No", 0.0)],
                    },
                    {
                        "text": "Is external network penetration testing performed annually?",
                        "question_type": "Radio",
                        "order": 2,
                        "help_text": "Testing should be conducted by a qualified third party.",
                        "choices": [("Yes", 10.0), ("No", 0.0)],
                    },
                ],
            },
            {
                "name": "Backup & Recovery",
                "order": 2,
                "questions": [
                    {
                        "text": "Upload evidence of the latest backup restoration test.",
                        "question_type": "Evidence",
                        "order": 1,
                        "help_text": "Attach a PDF, TXT, or exported backup log.",
                    },
                    {
                        "text": "What is the backup retention period in days?",
                        "question_type": "Numeric",
                        "order": 2,
                    },
                ],
            },
            {
                "name": "Access Control",
                "order": 3,
                "questions": [
                    {
                        "text": "Select all access controls enforced for administrative systems:",
                        "question_type": "MultiSelect",
                        "order": 1,
                        "choices": [("MFA", 5.0), ("IP Whitelisting", 3.0), ("Role-Based Access Control", 2.0)],
                    },
                ],
            },
        ],
        "ranges": [("High Exposure", 0.0, 15.0, "danger"), ("Medium Exposure", 15.1, 30.0, "warning"), ("Low Exposure", 30.1, 40.0, "success")],
    },
    {
        "name": "Supplier Assessment",
        "description": "Evaluate vendor security governance, data protection, and certification alignment.",
        "sections": [
            {
                "name": "Security Governance",
                "order": 1,
                "questions": [
                    {
                        "text": "Do you maintain a documented Information Security Policy?",
                        "question_type": "Dropdown",
                        "order": 1,
                        "choices": [("Yes, fully implemented", 10.0), ("Draft / In Progress", 5.0), ("No", 0.0)],
                    },
                    {
                        "text": "Have all employees completed annual security awareness training?",
                        "question_type": "Radio",
                        "order": 2,
                        "choices": [("Yes", 10.0), ("No", 0.0)],
                    },
                ],
            },
            {
                "name": "Data Protection",
                "order": 2,
                "questions": [
                    {"text": "What is the primary country/region where client data is hosted?", "question_type": "Text", "order": 1},
                    {"text": "Please upload your latest ISO 27001 Certificate or SOC 2 Report.", "question_type": "Evidence", "order": 2},
                ],
            },
        ],
        "ranges": [("Unacceptable Supplier Risk", 0.0, 10.0, "danger"), ("Acceptable Supplier Risk", 10.1, 20.0, "success")],
    },
    {
        "name": "CAF Assessment",
        "description": "Cyber Assessment Framework evaluation for critical infrastructure.",
        "sections": [
            {
                "name": "A1 Cyber Security Governance",
                "order": 1,
                "questions": [
                    {
                        "text": "Is there a board-level individual with overall responsibility for cyber security?",
                        "question_type": "Dropdown",
                        "order": 1,
                        "choices": [("Yes, clearly defined", 10.0), ("Informally assigned", 5.0), ("No board-level owner", 0.0)],
                    },
                ],
            },
            {
                "name": "B2 Identity & Access Control",
                "order": 2,
                "questions": [
                    {
                        "text": "Is Multi-Factor Authentication mandated for all remote access?",
                        "question_type": "Radio",
                        "order": 1,
                        "choices": [("Mandated and enforced", 10.0), ("Encouraged but not enforced", 5.0), ("No MFA", 0.0)],
                    },
                ],
            },
            {"name": "C1 Response Planning", "order": 3, "questions": [{"text": "Upload the Incident Response Plan.", "question_type": "Evidence", "order": 1}]},
        ],
        "ranges": [("CAF Achievement Not Met", 0.0, 15.0, "danger"), ("CAF Achievement Partially Met", 15.1, 25.0, "warning"), ("CAF Achievement Fully Met", 25.1, 30.0, "success")],
    },
    {
        "name": "ISO 27001 Assessment",
        "description": "Self-assessment against Annex A controls of ISO/IEC 27001.",
        "sections": [
            {
                "name": "A.5 Information Security Policies",
                "order": 1,
                "questions": [
                    {
                        "text": "Are information security policies reviewed at planned intervals?",
                        "question_type": "Dropdown",
                        "order": 1,
                        "choices": [("Yes, at least annually", 10.0), ("Ad-hoc reviews only", 5.0), ("No review process", 0.0)],
                    },
                ],
            },
            {
                "name": "A.9 Access Control",
                "order": 2,
                "questions": [
                    {
                        "text": "Select access management controls implemented:",
                        "question_type": "MultiSelect",
                        "order": 1,
                        "choices": [("User registration/deregistration", 4.0), ("Access rights provisioning", 4.0), ("Review of user access rights", 2.0)],
                    },
                ],
            },
        ],
        "ranges": [("ISO 27001 Non-Compliance", 0.0, 12.0, "danger"), ("ISO 27001 Major Alignment", 12.1, 20.0, "success")],
    },
    {
        "name": "DPIA Assessment",
        "description": "Data Protection Impact Assessment to evaluate GDPR privacy risks.",
        "sections": [
            {
                "name": "Need for DPIA",
                "order": 1,
                "questions": [
                    {"text": "Does the project involve systematic and extensive profiling of individuals?", "question_type": "Dropdown", "order": 1, "choices": [("Yes (High Risk)", 0.0), ("No", 10.0)]},
                    {"text": "Does the processing involve large-scale sensitive personal data?", "question_type": "Dropdown", "order": 2, "choices": [("Yes (High Risk)", 0.0), ("No", 10.0)]},
                ],
            },
            {
                "name": "GDPR Compliance Measures",
                "order": 2,
                "questions": [
                    {"text": "Describe measures to comply with GDPR lawful basis requirements.", "question_type": "LongText", "order": 1},
                    {"text": "What is the maximum retention period of personal data in months?", "question_type": "Numeric", "order": 2},
                ],
            },
        ],
        "ranges": [("High Privacy Risk", 0.0, 10.0, "danger"), ("Low Privacy Risk", 10.1, 20.0, "success")],
    },
    {
        "name": "Cyber Essentials Assessment",
        "description": "UK Government-backed scheme self-assessment questionnaire.",
        "sections": [
            {
                "name": "Firewalls",
                "order": 1,
                "questions": [
                    {"text": "Are default administrative passwords changed on all internet-connected devices?", "question_type": "Dropdown", "order": 1, "choices": [("Yes, on all devices", 10.0), ("On most devices", 5.0), ("No", 0.0)]},
                ],
            },
            {
                "name": "Secure Configuration",
                "order": 2,
                "questions": [
                    {"text": "Are unused user accounts and services disabled or removed?", "question_type": "Radio", "order": 1, "choices": [("Yes, regularly audited", 10.0), ("No", 0.0)]},
                ],
            },
            {
                "name": "Patch Management",
                "order": 3,
                "questions": [
                    {"text": "Are high-risk security updates applied within 14 days of release?", "question_type": "Dropdown", "order": 1, "choices": [("Always within 14 days", 10.0), ("Sometimes / Delayed", 5.0), ("No", 0.0)]},
                ],
            },
        ],
        "ranges": [("Fail", 0.0, 20.0, "danger"), ("Pass", 20.1, 30.0, "success")],
    },
]


def seed_reference_data(tenant, stdout=None):
    set_current_tenant(tenant)
    try:
        methodology, _ = AssessmentMethodology.objects.get_or_create(
            tenant=tenant,
            name="RiskPilot Standard Methodology",
            defaults={"description": "Threat-Vulnerability-Impact risk methodology.", "is_active": True},
        )
        version, _ = AssessmentMethodologyVersion.objects.get_or_create(
            tenant=tenant,
            methodology=methodology,
            version_number="1.0",
            defaults={"is_active": True},
        )

        for label, score in [("<1/year", 1), ("1/month to 1/year", 2), ("1/month", 3)]:
            ThreatFrequencyCriteria.objects.get_or_create(tenant=tenant, methodology_version=version, label=label, defaults={"score": score})
        for label, score in [("<1%", 1), ("1% to 20%", 2), ("20%", 3)]:
            VulnerabilityProbabilityCriteria.objects.get_or_create(tenant=tenant, methodology_version=version, label=label, defaults={"score": score})
        for score_value, label in [(1, "Very Low"), (2, "Low"), (3, "Medium"), (4, "High"), (5, "High"), (6, "Very High")]:
            LikelihoodCriteria.objects.get_or_create(tenant=tenant, methodology_version=version, score_value=score_value, defaults={"label": label})
        for label, score, desc, impact_range in [
            ("Insignificant", 1, "Minimal client impact. No fines. No commercial consequence.", "No financial impact"),
            ("Minor", 2, "Limited client dissatisfaction. Minor competitive impact.", "< 50000"),
            ("Moderate", 3, "Multiple clients affected. Low level penalties.", "50000 to 250000"),
            ("High", 4, "Major client loss. Significant penalties.", "10% to 20% of turnover"),
            ("Major", 5, "Business threatening event. Potential prosecution.", "> 20% of turnover"),
        ]:
            ImpactCriteria.objects.get_or_create(
                tenant=tenant,
                methodology_version=version,
                label=label,
                defaults={"score": score, "description": desc, "financial_impact_range": impact_range},
            )
        for label, min_score, max_score in [("Low", 1, 4), ("Medium", 5, 15), ("High", 16, 30)]:
            RiskCategory.objects.get_or_create(tenant=tenant, methodology_version=version, label=label, defaults={"min_score": min_score, "max_score": max_score})

        for category_name, threat_names in THREAT_LIBRARY.items():
            category, _ = ThreatCategory.objects.get_or_create(tenant=tenant, name=category_name)
            for threat_name in threat_names:
                Threat.objects.get_or_create(tenant=tenant, category=category, name=threat_name)

        for template_data in get_seed_templates():
            template, created = AssessmentTemplate.objects.get_or_create(
                tenant=tenant,
                name=template_data["name"],
                defaults={
                    "description": template_data["description"],
                    "version": 1,
                    "state": "Published",
                    "is_latest": True,
                },
            )
            if not created:
                template.description = template_data["description"]
                template.version = 1
                template.state = "Published"
                template.is_latest = True
                template.save(update_fields=["description", "version", "state", "is_latest", "updated_at"])
                TemplateSection.objects.filter(tenant=tenant, template=template).delete()
                TemplateScoringRange.objects.filter(tenant=tenant, template=template).delete()
            for section_data in template_data["sections"]:
                section = TemplateSection.objects.create(
                    tenant=tenant,
                    template=template,
                    name=section_data["name"],
                    description=section_data.get("description", ""),
                    order=section_data["order"],
                )
                for question_data in section_data["questions"]:
                    question = TemplateQuestion.objects.create(
                        tenant=tenant,
                        section=section,
                        text=question_data["text"],
                        question_type=question_data["question_type"],
                        is_required=question_data.get("is_required", True),
                        order=question_data["order"],
                        help_text=question_data.get("help_text", ""),
                        guidance_notes=question_data.get("guidance_notes", ""),
                    )
                    for index, (choice_text, score) in enumerate(question_data.get("choices", []), 1):
                        QuestionChoice.objects.create(question=question, text=choice_text, score=score, order=index)
            for label, min_score, max_score, color in template_data["ranges"]:
                TemplateScoringRange.objects.create(
                    tenant=tenant,
                    template=template,
                    label=label,
                    min_score=min_score,
                    max_score=max_score,
                    color=color,
                )

        if stdout:
            stdout.write(f"Seeded base reference data for tenant '{tenant.name}'.")
        return version
    finally:
        clear_current_tenant()


class Command(BaseCommand):
    help = "Seeds base/reference data for a tenant: methodology, scoring lookups, threat library, and assessment templates."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-domain", required=True, help="Tenant domain to seed.")

    def handle(self, *args, **options):
        tenant = Tenant.objects.filter(domain=options["tenant_domain"]).first()
        if not tenant:
            raise CommandError(f"Tenant with domain '{options['tenant_domain']}' does not exist.")
        seed_reference_data(tenant, self.stdout)
