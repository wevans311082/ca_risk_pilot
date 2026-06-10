from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Compatibility wrapper. Seeds optional demo data; use seed_base_data for production-safe reference data."

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("seed_sample_data is deprecated. Running seed_demo_data instead."))
        call_command("seed_demo_data")
