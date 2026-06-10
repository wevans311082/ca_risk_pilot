from datetime import date

from django.core.management.base import BaseCommand

from accounts.models import User
from assessments.management.commands.seed_base_data import seed_reference_data
from assessments.models import (
    Assessment,
    AssessmentMethodologyVersion,
    ImpactCriteria,
    RiskItem,
    RiskTreatment,
    Threat,
    ThreatFrequencyCriteria,
    VulnerabilityProbabilityCriteria,
)
from tenants.isolation import clear_current_tenant, set_current_tenant
from tenants.models import Client, Tenant, UserTenantMembership


class Command(BaseCommand):
    help = "Seeds an optional demo tenant, demo client, and sample assessment data."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-domain", default="cybercorp")
        parser.add_argument("--tenant-name", default="Cyber Security Tenant")

    def handle(self, *args, **options):
        tenant, created = Tenant.objects.get_or_create(
            domain=options["tenant_domain"],
            defaults={"name": options["tenant_name"], "status": "active"},
        )
        self.stdout.write(self.style.SUCCESS(f"{'Created' if created else 'Using'} demo tenant '{tenant.name}'."))

        seed_reference_data(tenant, self.stdout)
        set_current_tenant(tenant)
        try:
            admin_user, created_user = User.objects.get_or_create(
                email="admin@riskpilot.local",
                defaults={"username": "admin@riskpilot.local", "is_staff": True, "is_superuser": True},
            )
            if created_user:
                admin_user.set_password("AdminPassword123")
                admin_user.save()
            UserTenantMembership.objects.get_or_create(user=admin_user, tenant=tenant, defaults={"role": "owner"})

            client, _ = Client.objects.get_or_create(
                tenant=tenant,
                name="Alpha Corp Inc",
                defaults={"email": "info@alphacorp.com", "phone": "555-0199"},
            )

            version = AssessmentMethodologyVersion.objects.get(tenant=tenant, methodology__name="RiskPilot Standard Methodology", version_number="1.0")
            freq_low = ThreatFrequencyCriteria.objects.get(tenant=tenant, methodology_version=version, score=1)
            freq_med = ThreatFrequencyCriteria.objects.get(tenant=tenant, methodology_version=version, score=2)
            prob_low = VulnerabilityProbabilityCriteria.objects.get(tenant=tenant, methodology_version=version, score=1)
            prob_med = VulnerabilityProbabilityCriteria.objects.get(tenant=tenant, methodology_version=version, score=2)
            impact_minor = ImpactCriteria.objects.get(tenant=tenant, methodology_version=version, score=2)
            impact_moderate = ImpactCriteria.objects.get(tenant=tenant, methodology_version=version, score=3)
            impact_high = ImpactCriteria.objects.get(tenant=tenant, methodology_version=version, score=4)
            theft = Threat.objects.get(tenant=tenant, name="Theft of Data")
            ac_failure = Threat.objects.get(tenant=tenant, name="Failure of Air Conditioning")

            assessment, _ = Assessment.objects.get_or_create(
                tenant=tenant,
                client=client,
                methodology_version=version,
                name="2026 Core Infrastructure Assessment",
                defaults={
                    "change_request": "CR-4091: Migrate core customer DB backends.",
                    "asset": "Customer Database Server",
                    "location": "AWS Dublin Region",
                    "owner": "CISO Office",
                    "threat": theft,
                    "vulnerability": "Unpatched remote execution vulnerability on host machine.",
                    "existing_controls": "Basic firewall rules and subnet separation.",
                    "business_process_impact": "Exposure of customer database leads to major business impact.",
                    "confidentiality_affected": True,
                    "integrity_affected": True,
                    "availability_affected": True,
                    "status": "InProgress",
                },
            )

            risk_one, _ = RiskItem.objects.get_or_create(
                tenant=tenant,
                assessment=assessment,
                asset_name="Customer Database Backups",
                defaults={
                    "asset_location": "S3 Backups Dublin",
                    "asset_owner": "Database Operations Team",
                    "threat": theft,
                    "vulnerability": "Lack of encryption at rest for legacy backups.",
                    "existing_controls": "Access control lists restricted to server subnets.",
                    "confidentiality_affected": True,
                    "threat_frequency": freq_med,
                    "vulnerability_probability": prob_med,
                    "impact_severity": impact_high,
                    "proposed_controls": "Implement server-side encryption with managed keys.",
                    "residual_threat_frequency": freq_low,
                    "residual_vulnerability_probability": prob_low,
                    "residual_impact_severity": impact_minor,
                },
            )
            RiskTreatment.objects.get_or_create(
                tenant=tenant,
                risk_item=risk_one,
                defaults={"action": "Migrate backup buckets to managed-key encryption.", "owner": "Head of Data Engineering", "target_date": date(2026, 8, 1), "status": "In Progress"},
            )

            risk_two, _ = RiskItem.objects.get_or_create(
                tenant=tenant,
                assessment=assessment,
                asset_name="AC Units in On-Premise Server Closet",
                defaults={
                    "asset_location": "London office server room",
                    "asset_owner": "Facilities Manager",
                    "threat": ac_failure,
                    "vulnerability": "Older HVAC systems with no secondary backup.",
                    "existing_controls": "Temperature sensor alerts by SMS.",
                    "availability_affected": True,
                    "threat_frequency": freq_med,
                    "vulnerability_probability": prob_med,
                    "impact_severity": impact_moderate,
                },
            )
            RiskTreatment.objects.get_or_create(tenant=tenant, risk_item=risk_two, defaults={"status": "Open"})

            self.stdout.write(self.style.SUCCESS("Demo data seeding finished successfully."))
        finally:
            clear_current_tenant()
