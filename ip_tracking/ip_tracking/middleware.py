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
    Robust IP extraction that accounts for X-Forwarded-For headers.
    Adjust this based on your reverse proxy configuration.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # X-Forwarded-For may contain multiple IPs: client, proxy1, proxy2...
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Combined middleware that:
    1. Blocks blacklisted IPs (via BlockedIP model).
    2. Logs each request (via RequestLog model).
    3. Enriches logs with geolocation data (country, city) using django-ip-geolocation.
       Caches geolocation info for 24 hours per IP.

    Add to settings.py:
        MIDDLEWARE = [
            'ip_tracking.middleware.IPTrackingMiddleware',
            ...
        ]
    """

    def process_request(self, request):
        ip = get_client_ip(request)
        path = request.path
        timestamp = timezone.now()

        # 1️⃣ Block blacklisted IPs
        if ip and BlockedIP.objects.filter(ip_address=ip).exists():
            logger.warning(f"Blocked IP tried to access: {ip}")
            return HttpResponseForbidden("Forbidden: your IP address is blocked.")

        # 2️⃣ Geolocation (with 24h caching)
        cache_key = f"geo:{ip}"
        geo = cache.get(cache_key)

        if geo is None:
            geoloc = getattr(request, "geolocation", None)
            country = None
            city = None

            if geoloc:
                # Try multiple shapes depending on django-ipgeolocation version
                try:
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
            cache.set(cache_key, geo, 24 * 3600)  # cache for 24 hours

        # 3️⃣ Log request (with geolocation)
        try:
            RequestLog.objects.create(
                ip_address=ip,
                timestamp=timestamp,
                path=path,
                country=geo.get("country"),
                city=geo.get("city"),
            )
            logger.info(f"RequestLog saved for IP={ip}, path={path}, country={geo.get('country')}, city={geo.get('city')}")
        except Exception as e:
            logger.exception(f"Failed to save RequestLog: {e}")

        # Continue request chain
        return None
