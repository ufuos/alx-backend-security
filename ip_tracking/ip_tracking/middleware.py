# ip_tracking/middleware.py

from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.core.cache import cache
import logging
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """
    Extract client IP address considering possible proxy headers.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # X-Forwarded-For may contain multiple IPs: client, proxy1, proxy2...
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip or "0.0.0.0"


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware that:
    1. Blocks blacklisted IPs (via BlockedIP model).
    2. Logs each request (via RequestLog model).
    3. Optionally enriches logs with geolocation (if available).
       Caches geolocation for 24 hours per IP.

    Add to settings.py:
        MIDDLEWARE = [
            'ip_tracking.middleware.IPTrackingMiddleware',
            ...
        ]
    """

    def process_request(self, request):
        ip = get_client_ip(request)
        path = request.path
        method = request.method
        timestamp = timezone.now()

        # 1️⃣ Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            logger.warning(f"Blocked IP tried to access: {ip}")
            return HttpResponseForbidden("Forbidden: your IP address is blocked.")

        # 2️⃣ Retrieve or cache geolocation info
        cache_key = f"geo:{ip}"
        geo = cache.get(cache_key)

        if geo is None:
            geoloc = getattr(request, "geolocation", None)
            country = None
            city = None

            if geoloc:
                try:
                    # Handle multiple structures depending on django-ipgeolocation version
                    if hasattr(geoloc, "country"):
                        c = geoloc.country
                        if isinstance(c, dict):
                            country = c.get("name")
                        else:
                            country = c
                    city = getattr(geoloc, "city", None) or getattr(geoloc, "_city", None)
                    if isinstance(city, dict):
                        city = city.get("name") or city.get("city")
                except Exception:
                    pass

            geo = {"country": country, "city": city}
            cache.set(cache_key, geo, 24 * 3600)  # Cache for 24 hours

        # 3️⃣ Log the request
        try:
            RequestLog.objects.create(
                ip_address=ip,
                path=path,
                method=method,
                timestamp=timestamp,
                country=geo.get("country"),
                city=geo.get("city"),
            )
            logger.info(
                f"Logged: IP={ip}, path={path}, method={method}, "
                f"country={geo.get('country')}, city={geo.get('city')}"
            )
        except Exception as e:
            logger.exception(f"Failed to log request for IP={ip}: {e}")

        # Continue request chain
        return None
