from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.db import transaction

from tenants.isolation import clear_current_tenant, set_current_tenant
from tenants.models import Tenant, UserTenantMembership


class Command(BaseCommand):
    help = "Bootstrap RiskPilot after migrations: collect static files, create tenant, and create/update the first admin user."

    def add_arguments(self, parser):
        parser.add_argument(
            "--skip-collectstatic",
            action="store_true",
            help="Do not run collectstatic.",
        )

    def handle(self, *args, **options):
        if not options["skip_collectstatic"]:
            self.stdout.write("Collecting static files...")
            call_command("collectstatic", interactive=False, verbosity=0)

        tenant_name = getattr(settings, "BOOTSTRAP_TENANT_NAME", "RiskPilot Local")
        tenant_domain = getattr(settings, "BOOTSTRAP_TENANT_DOMAIN", "local")
        username = getattr(settings, "BOOTSTRAP_SUPERUSER_USERNAME", "admin@riskpilot.local")
        email = getattr(settings, "BOOTSTRAP_SUPERUSER_EMAIL", username)
        password = getattr(settings, "BOOTSTRAP_SUPERUSER_PASSWORD", "")

        if not password:
            self.stdout.write(self.style.WARNING("DJANGO_SUPERUSER_PASSWORD is empty; admin user creation skipped."))
            return

        User = get_user_model()

        with transaction.atomic():
            tenant, tenant_created = Tenant.objects.get_or_create(
                domain=tenant_domain,
                defaults={
                    "name": tenant_name,
                    "status": "active",
                },
            )
            if tenant_created:
                self.stdout.write(self.style.SUCCESS(f"Created tenant '{tenant.name}' ({tenant.domain})."))
            else:
                self.stdout.write(f"Using tenant '{tenant.name}' ({tenant.domain}).")

            set_current_tenant(tenant)
            try:
                user, user_created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "username": username,
                        "is_staff": True,
                        "is_superuser": True,
                    },
                )
                user.username = username
                user.is_staff = True
                user.is_superuser = True
                if user_created:
                    user.set_password(password)
                    self.stdout.write(self.style.SUCCESS(f"Created superuser '{email}'."))
                else:
                    self.stdout.write(f"Using superuser '{email}'.")
                user.save()

                UserTenantMembership.objects.update_or_create(
                    user=user,
                    tenant=tenant,
                    defaults={"role": "owner"},
                )
                self.stdout.write(self.style.SUCCESS(f"Ensured owner membership for '{email}' in '{tenant.name}'."))
            finally:
                clear_current_tenant()
