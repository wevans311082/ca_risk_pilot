from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import date
from tenants.models import Tenant, Client, UserTenantMembership
from accounts.models import User
from tenants.isolation import set_current_tenant, clear_current_tenant
from assessments.models import (
    AssessmentMethodology, AssessmentMethodologyVersion,
    ThreatFrequencyCriteria, VulnerabilityProbabilityCriteria, LikelihoodCriteria,
    ImpactCriteria, RiskCategory, ThreatCategory, Threat, Assessment, RiskItem, RiskTreatment,
    AssessmentTemplate, TemplateSection, TemplateQuestion, QuestionChoice,
    TemplateScoringRange, TemplateAssessment, TemplateAnswer
)

class Command(BaseCommand):
    help = 'Seeds the database with the new risk assessment methodology, threat library, and a sample assessment.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Starting sample data seeding..."))
        
        # 1. Create Tenant
        tenant, created = Tenant.objects.get_or_create(
            domain="cybercorp",
            defaults={
                "name": "Cyber Security Tenant",
                "status": "active"
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"Created Tenant: {tenant.name}"))
        else:
            self.stdout.write(f"Using existing Tenant: {tenant.name}")

        # Set tenant context
        set_current_tenant(tenant)
        
        try:
            # 2. Create local admin user for testing if it doesn't exist
            admin_user, created_user = User.objects.get_or_create(
                email="admin@riskpilot.local",
                defaults={
                    "username": "admin@riskpilot.local",
                    "is_staff": True,
                    "is_superuser": True
                }
            )
            if created_user:
                admin_user.set_password("AdminPassword123")
                admin_user.save()
                self.stdout.write(self.style.SUCCESS("Created admin user admin@riskpilot.local"))
                
            # Establish membership in Tenant
            UserTenantMembership.objects.get_or_create(
                user=admin_user,
                tenant=tenant,
                defaults={"role": "owner"}
            )

            # 3. Create Client
            client, created = Client.objects.get_or_create(
                tenant=tenant,
                name="Alpha Corp Inc",
                defaults={
                    "email": "info@alphacorp.com",
                    "phone": "555-0199"
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created Client: {client.name}"))

            # 4. Create Methodology & Methodology Version
            methodology, created = AssessmentMethodology.objects.get_or_create(
                tenant=tenant,
                name="RiskPilot Standard Methodology",
                defaults={
                    "description": "Comprehensive Threat-Vulnerability-Impact Risk Methodology.",
                    "is_active": True
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created Methodology: {methodology.name}"))

            version, created = AssessmentMethodologyVersion.objects.get_or_create(
                tenant=tenant,
                methodology=methodology,
                version_number="1.0",
                defaults={"is_active": True}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created Methodology Version: {version.version_number}"))

            # 5. Populate Scoring Lookups under Version 1.0
            # --- Threat Frequency Criteria ---
            freq_data = [
                ("<1/year", 1),
                ("1/month to 1/year", 2),
                ("1/month", 3),
            ]
            freq_objs = {}
            for label, score in freq_data:
                obj, _ = ThreatFrequencyCriteria.objects.get_or_create(
                    tenant=tenant, methodology_version=version, label=label, defaults={"score": score}
                )
                freq_objs[score] = obj

            # --- Vulnerability Probability Criteria ---
            prob_data = [
                ("<1%", 1),
                ("1% to 20%", 2),
                ("20%", 3),
            ]
            prob_objs = {}
            for label, score in prob_data:
                obj, _ = VulnerabilityProbabilityCriteria.objects.get_or_create(
                    tenant=tenant, methodology_version=version, label=label, defaults={"score": score}
                )
                prob_objs[score] = obj

            # --- Likelihood Calculation (Threat + Vulnerability sum lookup) ---
            like_data = [
                (1, "Very Low"),
                (2, "Low"),
                (3, "Medium"),
                (4, "High"),
                (5, "High"),
                (6, "Very High"),
            ]
            for val, label in like_data:
                LikelihoodCriteria.objects.get_or_create(
                    tenant=tenant, methodology_version=version, score_value=val, defaults={"label": label}
                )

            # --- Impact Severity Criteria ---
            impact_data = [
                ("Insignificant", 1, "Minimal client impact\nNo fines\nNo commercial consequence", "No financial impact"),
                ("Minor", 2, "Limited client dissatisfaction\nMinor competitive impact\nFinancial impact less than £50,000", "< £50,000"),
                ("Moderate", 3, "Multiple clients affected\nLow level penalties\nFinancial impact £50,000 to £250,000", "£50,000 to £250,000"),
                ("High", 4, "Major client loss\nSignificant penalties\nFinancial impact 10% to 20% of turnover", "10% to 20% of turnover"),
                ("Major", 5, "Business threatening event\nPotential prosecution\nPotential business failure\nFinancial impact greater than 20% of turnover", "> 20% of turnover"),
            ]
            impact_objs = {}
            for label, score, desc, f_range in impact_data:
                obj, _ = ImpactCriteria.objects.get_or_create(
                    tenant=tenant,
                    methodology_version=version,
                    label=label,
                    defaults={
                        "score": score,
                        "description": desc,
                        "financial_impact_range": f_range
                    }
                )
                impact_objs[score] = obj

            # --- Risk Category Thresholds ---
            risk_cats = [
                ("Low", 1, 4),
                ("Medium", 5, 15),
                ("High", 16, 30),
            ]
            for label, min_s, max_s in risk_cats:
                RiskCategory.objects.get_or_create(
                    tenant=tenant, methodology_version=version, label=label, defaults={"min_score": min_s, "max_score": max_s}
                )
            
            self.stdout.write("Configured database-driven scoring lookup tables.")

            # 6. Seed Configurable Threat Library Catalogue
            threat_library = {
                "Physical Damage": [
                    "Fire", "Water Damage", "Pollution", "Major Accident", 
                    "Destruction of Equipment", "Dust Corrosion Freezing"
                ],
                "Natural Events": [
                    "Climatic Phenomenon", "Seismic Phenomenon", "Volcanic Phenomenon", "Flood", "Pandemic"
                ],
                "Loss of Essential Services": [
                    "Failure of Air Conditioning", "Failure of Power Supply", "Failure of Telecommunications", "Fuel Shortage"
                ],
                "Technical Failures": [
                    "Hardware Failure", "Software Failure", "Network Failure", "Data Corruption"
                ],
                "Unauthorised Actions": [
                    "Sharing of Access Privileges", "Malicious Insider Activity", "Privilege Abuse", "Unauthorised Access"
                ],
                "Compromise of Information": [
                    "Loss of Data", "Disclosure of Data", "Theft of Data", "Incorrect Modification"
                ],
                "Compromise of Functions": [
                    "Service Interruption", "Supplier Failure", "Cloud Service Outage"
                ]
            }

            threat_objs = {}
            for cat_name, threats_list in threat_library.items():
                cat_obj, _ = ThreatCategory.objects.get_or_create(tenant=tenant, name=cat_name)
                for t_name in threats_list:
                    t_obj, _ = Threat.objects.get_or_create(
                        tenant=tenant, category=cat_obj, name=t_name
                    )
                    threat_objs[t_name] = t_obj

            self.stdout.write(f"Seeded configurable Threat Library: {Threat.objects.count()} threats created.")

            # 7. Create Assessment Run
            assessment, created = Assessment.objects.get_or_create(
                tenant=tenant,
                client=client,
                methodology_version=version,
                name="2026 Core Infrastructure Assessment",
                defaults={
                    "change_request": "CR-4091: Migrate core customer DB backends.",
                    "asset": "Customer Database Server",
                    "location": "AWS Dublin Region",
                    "owner": "CISO Office",
                    "threat": threat_objs["Theft of Data"],
                    "vulnerability": "Unpatched remote execution vulnerability on host machine.",
                    "existing_controls": "Basic firewall rules and network subnets separation.",
                    "business_process_impact": "Exposure of customer database leads to business failure.",
                    "confidentiality_affected": True,
                    "integrity_affected": True,
                    "availability_affected": True,
                    "status": "InProgress"
                }
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created Assessment Run: {assessment.name}"))

            # 8. Create Risk Items inside Assessment
            # Risk Item 1: Database Theft Risk (High Inherent, Low Residual after treatment)
            ri1, created = RiskItem.objects.get_or_create(
                tenant=tenant,
                assessment=assessment,
                asset_name="Customer Database Backups",
                defaults={
                    "asset_location": "S3 Backups Dublin",
                    "asset_owner": "Database Operations Team",
                    "threat": threat_objs["Theft of Data"],
                    "vulnerability": "Lack of encryption at rest for legacy database backups.",
                    "existing_controls": "Access control lists restricted to server subnets.",
                    "confidentiality_affected": True,
                    "integrity_affected": False,
                    "availability_affected": False,
                    "threat_frequency": freq_objs[2],         # 1/month to 1/year (2)
                    "vulnerability_probability": prob_objs[2], # 1% to 20% (2) -> combined Likelihood = 4
                    "impact_severity": impact_objs[4],          # High (4) -> Inherent Score = 16 (High)
                    "proposed_controls": "Implement S3 server-side encryption via KMS key integration.",
                    "additional_mitigations": "Restrict IAM S3 bucket operations to admin profiles.",
                    "residual_threat_frequency": freq_objs[1],         # <1/year (1)
                    "residual_vulnerability_probability": prob_objs[1], # <1% (1) -> combined Likelihood = 2
                    "residual_impact_severity": impact_objs[2]          # Minor (2) -> Residual Score = 4 (Low)
                }
            )
            if created:
                self.stdout.write(f"Created Risk Item: {ri1.asset_name} (Inherent Risk: {ri1.risk_score})")

            # Risk Item 1 Treatment record
            RiskTreatment.objects.get_or_create(
                tenant=tenant,
                risk_item=ri1,
                defaults={
                    "action": "Migrate backup buckets to KMS encryption and rotate encryption key hourly.",
                    "owner": "Head of Data Engineering",
                    "target_date": date(2026, 8, 1),
                    "status": "In Progress",
                    "completion_notes": ""
                }
            )

            # Risk Item 2: AC Unit Failure (Medium Inherent, Untreated)
            ri2, created = RiskItem.objects.get_or_create(
                tenant=tenant,
                assessment=assessment,
                asset_name="AC Units in On-Premise Server Closet",
                defaults={
                    "asset_location": "London Office server room",
                    "asset_owner": "Facilities Manager",
                    "threat": threat_objs["Failure of Air Conditioning"],
                    "vulnerability": "Older HVAC systems with no secondary backup.",
                    "existing_controls": "Temperature sensor that alerts by SMS.",
                    "confidentiality_affected": False,
                    "integrity_affected": False,
                    "availability_affected": True,
                    "threat_frequency": freq_objs[2],         # 1/month to 1/year (2)
                    "vulnerability_probability": prob_objs[2], # 1% to 20% (2) -> combined Likelihood = 4
                    "impact_severity": impact_objs[3],          # Moderate (3) -> Inherent Score = 12 (Medium)
                }
            )
            if created:
                self.stdout.write(f"Created Risk Item: {ri2.asset_name} (Inherent Risk: {ri2.risk_score})")

            # Risk Item 2 Treatment record (empty placeholder treatment)
            RiskTreatment.objects.get_or_create(
                tenant=tenant,
                risk_item=ri2,
                defaults={
                    "action": "",
                    "owner": "",
                    "target_date": None,
                    "status": "Open",
                    "completion_notes": ""
                }
            )

            # 9. Seed Dynamic Assessment Templates
            self.stdout.write("Seeding Dynamic Assessment Templates...")
            templates_data = [
                {
                    "name": "Cyber Risk Assessment",
                    "description": "Standard assessment of organization's cyber security posture including firewall, backups and access control.",
                    "sections": [
                        {
                            "name": "Network Security",
                            "order": 1,
                            "questions": [
                                {
                                    "text": "Are firewalls deployed at all network boundaries?",
                                    "question_type": "Dropdown",
                                    "is_required": True,
                                    "order": 1,
                                    "help_text": "Check all internet-facing entry points.",
                                    "guidance_notes": "We require firewalls to be configured to block all inbound traffic by default.",
                                    "choices": [
                                        {"text": "Yes", "score": 10.0, "order": 1},
                                        {"text": "Partial", "score": 5.0, "order": 2},
                                        {"text": "No", "score": 0.0, "order": 3}
                                    ]
                                },
                                {
                                    "text": "Is external network penetration testing performed annually?",
                                    "question_type": "Radio",
                                    "is_required": True,
                                    "order": 2,
                                    "help_text": "Testing must be conducted by a certified third party.",
                                    "choices": [
                                        {"text": "Yes", "score": 10.0, "order": 1},
                                        {"text": "No", "score": 0.0, "order": 2}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "Backup & Recovery",
                            "order": 2,
                            "questions": [
                                {
                                    "text": "Upload evidence of the latest backup restoration test.",
                                    "question_type": "Evidence",
                                    "is_required": True,
                                    "order": 1,
                                    "help_text": "Attach a PDF or TXT backup log.",
                                },
                                {
                                    "text": "What is the backup retention period in days?",
                                    "question_type": "Numeric",
                                    "is_required": True,
                                    "order": 2,
                                    "help_text": "Enter numerical value only."
                                }
                            ]
                        },
                        {
                            "name": "Access Control",
                            "order": 3,
                            "questions": [
                                {
                                    "text": "Select all access controls enforced for administrative systems:",
                                    "question_type": "MultiSelect",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "MFA", "score": 5.0, "order": 1},
                                        {"text": "IP Whitelisting", "score": 3.0, "order": 2},
                                        {"text": "Role-Based Access Control", "score": 2.0, "order": 3}
                                    ]
                                }
                            ]
                        }
                    ],
                    "ranges": [
                        {"label": "High Exposure", "min_score": 0.0, "max_score": 15.0, "color": "danger"},
                        {"label": "Medium Exposure", "min_score": 15.1, "max_score": 30.0, "color": "warning"},
                        {"label": "Low Exposure", "min_score": 30.1, "max_score": 40.0, "color": "success"}
                    ]
                },
                {
                    "name": "Supplier Assessment",
                    "description": "Evaluate vendor security governance, NDAs, and certification alignment.",
                    "sections": [
                        {
                            "name": "Security Governance",
                            "order": 1,
                            "questions": [
                                {
                                    "text": "Do you maintain a documented Information Security Policy?",
                                    "question_type": "Dropdown",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Yes, fully implemented", "score": 10.0, "order": 1},
                                        {"text": "Draft / In Progress", "score": 5.0, "order": 2},
                                        {"text": "No", "score": 0.0, "order": 3}
                                    ]
                                },
                                {
                                    "text": "Have all employees completed annual security awareness training?",
                                    "question_type": "Radio",
                                    "is_required": True,
                                    "order": 2,
                                    "choices": [
                                        {"text": "Yes", "score": 10.0, "order": 1},
                                        {"text": "No", "score": 0.0, "order": 2}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "Data Protection",
                            "order": 2,
                            "questions": [
                                {
                                    "text": "What is the primary country/region where client data is hosted?",
                                    "question_type": "Text",
                                    "is_required": True,
                                    "order": 1,
                                    "help_text": "e.g. UK, EU, US"
                                },
                                {
                                    "text": "Please upload your latest ISO 27001 Certificate or SOC 2 Report.",
                                    "question_type": "Evidence",
                                    "is_required": True,
                                    "order": 2
                                }
                            ]
                        }
                    ],
                    "ranges": [
                        {"label": "Unacceptable Supplier Risk", "min_score": 0.0, "max_score": 10.0, "color": "danger"},
                        {"label": "Acceptable Supplier Risk", "min_score": 10.1, "max_score": 20.0, "color": "success"}
                    ]
                },
                {
                    "name": "CAF Assessment",
                    "description": "Cyber Assessment Framework (CAF) evaluation for critical infrastructure.",
                    "sections": [
                        {
                            "name": "A1 Cyber Security Governance",
                            "order": 1,
                            "questions": [
                                {
                                    "text": "Is there a board-level individual with overall responsibility for cyber security?",
                                    "question_type": "Dropdown",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Yes, clearly defined", "score": 10.0, "order": 1},
                                        {"text": "Informally assigned", "score": 5.0, "order": 2},
                                        {"text": "No board-level owner", "score": 0.0, "order": 3}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "B2 Identity & Access Control",
                            "order": 2,
                            "questions": [
                                {
                                    "text": "Is Multi-Factor Authentication (MFA) mandated for all remote access?",
                                    "question_type": "Radio",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Mandated and enforced", "score": 10.0, "order": 1},
                                        {"text": "Encouraged but not enforced", "score": 5.0, "order": 2},
                                        {"text": "No MFA", "score": 0.0, "order": 3}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "C1 Response Planning",
                            "order": 3,
                            "questions": [
                                {
                                    "text": "Upload the Incident Response Plan.",
                                    "question_type": "Evidence",
                                    "is_required": True,
                                    "order": 1
                                }
                            ]
                        }
                    ],
                    "ranges": [
                        {"label": "CAF Achievement Not Met", "min_score": 0.0, "max_score": 15.0, "color": "danger"},
                        {"label": "CAF Achievement Partially Met", "min_score": 15.1, "max_score": 25.0, "color": "warning"},
                        {"label": "CAF Achievement Fully Met", "min_score": 25.1, "max_score": 30.0, "color": "success"}
                    ]
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
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Yes, at least annually", "score": 10.0, "order": 1},
                                        {"text": "Ad-hoc reviews only", "score": 5.0, "order": 2},
                                        {"text": "No review process", "score": 0.0, "order": 3}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "A.9 Access Control",
                            "order": 2,
                            "questions": [
                                {
                                    "text": "Select access management controls implemented:",
                                    "question_type": "MultiSelect",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "User registration/deregistration", "score": 4.0, "order": 1},
                                        {"text": "Access rights provisioning", "score": 4.0, "order": 2},
                                        {"text": "Review of user access rights", "score": 2.0, "order": 3}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "A.12 Operations Security",
                            "order": 3,
                            "questions": [
                                {
                                    "text": "Enter the date of the last malware scanning definition update:",
                                    "question_type": "Date",
                                    "is_required": False,
                                    "order": 1
                                }
                            ]
                        }
                    ],
                    "ranges": [
                        {"label": "ISO 27001 Non-Compliance", "min_score": 0.0, "max_score": 12.0, "color": "danger"},
                        {"label": "ISO 27001 Major Alignment", "min_score": 12.1, "max_score": 20.0, "color": "success"}
                    ]
                },
                {
                    "name": "DPIA Assessment",
                    "description": "Data Protection Impact Assessment to evaluate GDPR privacy risks.",
                    "sections": [
                        {
                            "name": "Need for DPIA",
                            "order": 1,
                            "questions": [
                                {
                                    "text": "Does the project involve systematic and extensive profiling of individuals?",
                                    "question_type": "Dropdown",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Yes (High Risk)", "score": 0.0, "order": 1},
                                        {"text": "No", "score": 10.0, "order": 2}
                                    ]
                                },
                                {
                                    "text": "Does the processing involve large-scale sensitive personal data (e.g. health, criminal)?",
                                    "question_type": "Dropdown",
                                    "is_required": True,
                                    "order": 2,
                                    "choices": [
                                        {"text": "Yes (High Risk)", "score": 0.0, "order": 1},
                                        {"text": "No", "score": 10.0, "order": 2}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "GDPR Compliance Measures",
                            "order": 2,
                            "questions": [
                                {
                                    "text": "Describe the measures envisaged to comply with GDPR lawful basis requirements.",
                                    "question_type": "LongText",
                                    "is_required": True,
                                    "order": 1
                                },
                                {
                                    "text": "What is the maximum retention period of personal data (in months)?",
                                    "question_type": "Numeric",
                                    "is_required": True,
                                    "order": 2
                                }
                            ]
                        }
                    ],
                    "ranges": [
                        {"label": "High Privacy Risk", "min_score": 0.0, "max_score": 10.0, "color": "danger"},
                        {"label": "Low Privacy Risk", "min_score": 10.1, "max_score": 20.0, "color": "success"}
                    ]
                },
                {
                    "name": "Cyber Essentials Assessment",
                    "description": "UK Government-backed scheme self-assessment questionnaire.",
                    "sections": [
                        {
                            "name": "Firewalls",
                            "order": 1,
                            "questions": [
                                {
                                    "text": "Are default administrative passwords changed on all internet-connected devices?",
                                    "question_type": "Dropdown",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Yes, on all devices", "score": 10.0, "order": 1},
                                        {"text": "On most devices", "score": 5.0, "order": 2},
                                        {"text": "No", "score": 0.0, "order": 3}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "Secure Configuration",
                            "order": 2,
                            "questions": [
                                {
                                    "text": "Are unused user accounts and services disabled or removed?",
                                    "question_type": "Radio",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Yes, regularly audited", "score": 10.0, "order": 1},
                                        {"text": "No", "score": 0.0, "order": 2}
                                    ]
                                }
                            ]
                        },
                        {
                            "name": "Patch Management",
                            "order": 3,
                            "questions": [
                                {
                                    "text": "Are high-risk security updates applied within 14 days of release?",
                                    "question_type": "Dropdown",
                                    "is_required": True,
                                    "order": 1,
                                    "choices": [
                                        {"text": "Always within 14 days", "score": 10.0, "order": 1},
                                        {"text": "Sometimes / Delayed", "score": 5.0, "order": 2},
                                        {"text": "No", "score": 0.0, "order": 3}
                                    ]
                                }
                            ]
                        }
                    ],
                    "ranges": [
                        {"label": "Fail", "min_score": 0.0, "max_score": 20.0, "color": "danger"},
                        {"label": "Pass", "min_score": 20.1, "max_score": 30.0, "color": "success"}
                    ]
                }
            ]

            for t_data in templates_data:
                tpl, created_t = AssessmentTemplate.objects.get_or_create(
                    tenant=tenant,
                    name=t_data["name"],
                    defaults={
                        "description": t_data["description"],
                        "version": 1,
                        "state": "Published",
                        "is_latest": True
                    }
                )
                if created_t:
                    self.stdout.write(f"Seeded template: {tpl.name}")
                    for s_data in t_data["sections"]:
                        sec = TemplateSection.objects.create(
                            tenant=tenant,
                            template=tpl,
                            name=s_data["name"],
                            order=s_data["order"]
                        )
                        for q_data in s_data["questions"]:
                            q = TemplateQuestion.objects.create(
                                tenant=tenant,
                                section=sec,
                                text=q_data["text"],
                                question_type=q_data["question_type"],
                                is_required=q_data.get("is_required", True),
                                order=q_data["order"],
                                help_text=q_data.get("help_text", ""),
                                guidance_notes=q_data.get("guidance_notes", "")
                            )
                            for c_data in q_data.get("choices", []):
                                QuestionChoice.objects.create(
                                    question=q,
                                    text=c_data["text"],
                                    score=c_data["score"],
                                    order=c_data["order"]
                                )
                    for r_data in t_data["ranges"]:
                        TemplateScoringRange.objects.create(
                            tenant=tenant,
                            template=tpl,
                            label=r_data["label"],
                            min_score=r_data["min_score"],
                            max_score=r_data["max_score"],
                            color=r_data["color"]
                        )

            self.stdout.write(self.style.SUCCESS("Sample data seeding finished successfully!"))

        finally:
            clear_current_tenant()
