from django.http import HttpResponseForbidden
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin  # optional compatibility import
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """
    Return the client's IP address, accounting for X-Forwarded-For headers.
    This works correctly even if the app is behind a reverse proxy.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # X-Forwarded-For may be a list of IPs: client, proxy1, proxy2...
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Combined middleware that:
    1. Blocks requests from blacklisted IPs (via BlockedIP model).
    2. Logs all incoming requests (via RequestLog model).

    Add this middleware to MIDDLEWARE in settings.py, preferably early.
    Example:
        MIDDLEWARE = [
            'ip_tracking.middleware.IPTrackingMiddleware',
            ...
        ]
    """

    def process_request(self, request):
        from .models import RequestLog, BlockedIP  # imported here to avoid AppRegistryNotReady error

        ip = get_client_ip(request)
        path = request.path
        timestamp = timezone.now()

        # --- 1️⃣ Check if IP is blacklisted ---
        if ip and BlockedIP.objects.filter(ip_address=ip).exists():
            logger.warning("Blocked IP tried to access: %s", ip)
            return HttpResponseForbidden("Forbidden: your IP address is blocked.")

        # --- 2️⃣ Log IP request info ---
        try:
            RequestLog.objects.create(
                ip_address=ip,
                timestamp=timestamp,
                path=path
            )
            logger.info("RequestLog - ip=%s path=%s time=%s", ip, path, timestamp.isoformat())
        except Exception as e:
            logger.exception("Failed to save RequestLog: %s", e)

        # No return → request continues to next middleware/view
        return None
