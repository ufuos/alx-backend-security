from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Add an IP address to the BlockedIP list."

    def add_arguments(self, parser):
        parser.add_argument(
            "ip_address",
            type=str,
            help="The IP address to block (e.g. 192.168.1.10)"
        )

    def handle(self, *args, **options):
        ip_address = options["ip_address"]

        # Validate IP address format using Django's built-in validator
        from django.core.validators import validate_ipv46_address
        from django.core.exceptions import ValidationError

        try:
            validate_ipv46_address(ip_address)
        except ValidationError:
            raise CommandError(f"'{ip_address}' is not a valid IPv4/IPv6 address.")

        # Check if IP already exists
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            self.stdout.write(self.style.WARNING(f"IP {ip_address} is already blocked."))
        else:
            BlockedIP.objects.create(ip_address=ip_address)
            self.stdout.write(self.style.SUCCESS(f"Successfully blocked IP: {ip_address}"))
