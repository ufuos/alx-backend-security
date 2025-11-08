# ip_tracking/tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.apps import apps
from django.conf import settings
from django.db.models import Count

# get models dynamically so code works whether models exist in same file or elsewhere
SuspiciousIP = apps.get_model("ip_tracking", "SuspiciousIP")

# Try to load a RequestLog-like model.
# If you added the RequestLog above, it will be found.
RequestLog = None
try:
    RequestLog = apps.get_model("ip_tracking", "RequestLog")
except LookupError:
    # If not found, you may have another model in your project that logs requests.
    # Replace 'yourapp.RequestLogModel' below or adapt this task to your existing model.
    RequestLog = None

@shared_task
def detect_suspicious_ips():
    """
    Detect IPs that exceed thresholds or access sensitive paths.
    This task is intended to run hourly (configured in Celery beat).
    """
    now = timezone.now()
    since = now - timedelta(hours=1)

    # fallback list of sensitive paths
    sensitive_paths = getattr(settings, "SENSITIVE_PATHS", ["/admin", "/login"])

    reasons = []
    flagged_ips = set()

    if RequestLog is None:
        # No RequestLog model found: nothing to analyze.
        # Optionally, you might log or alert here.
        return "No RequestLog model found; no analysis performed."

    # 1) Find IPs with >100 requests in the last hour
    qs_counts = (
        RequestLog.objects
        .filter(timestamp__gte=since)
        .values("ip_address")
        .annotate(count=Count("id"))
        .filter(count__gt=100)
    )

    for row in qs_counts:
        ip = row["ip_address"]
        count = row["count"]
        reason = f"{count} requests in the last hour (>100)"
        SuspiciousIP.objects.create(ip_address=ip, reason=reason)
        flagged_ips.add(ip)
        reasons.append((ip, reason))

    # 2) Find IPs that accessed sensitive paths in the last hour
    qs_sensitive = (
        RequestLog.objects
        .filter(timestamp__gte=since, path__in=sensitive_paths)
        .values("ip_address")
        .distinct()
    )

    for row in qs_sensitive:
        ip = row["ip_address"]
        if ip in flagged_ips:
            # already flagged for other reason — optionally append an additional record
            reason = "accessed sensitive path(s) in last hour"
            SuspiciousIP.objects.create(ip_address=ip, reason=reason)
            reasons.append((ip, reason))
        else:
            reason = "accessed sensitive path(s) in last hour"
            SuspiciousIP.objects.create(ip_address=ip, reason=reason)
            flagged_ips.add(ip)
            reasons.append((ip, reason))

    return f"Flagged {len(flagged_ips)} suspicious IP(s)"
