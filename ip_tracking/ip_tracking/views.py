# ip_tracking/views.py
from django.http import HttpResponse, JsonResponse
from ratelimit.core import is_ratelimited
from functools import wraps

# A decorator that applies different IP-based rates depending on auth status.
def ip_rate_limit(methods=None):
    """
    Use as @ip_rate_limit(methods=['POST']) or @ip_rate_limit()
    Default checks GET and POST.
    """
    if methods is None:
        methods = ['GET', 'POST']

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # choose rate based on authentication
            if request.user and request.user.is_authenticated:
                rate = "10/m"
            else:
                rate = "5/m"

            # is_ratelimited will check & optionally increment the counter.
            # increment=True -> count this request in the rate window
            limited = is_ratelimited(request=request,
                                     key="ip",
                                     rate=rate,
                                     method=methods,
                                     increment=True)
            if limited:
                # 429 Too Many Requests
                return HttpResponse(
                    "Too many requests. Try again later.",
                    status=429
                )
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

# Example: apply to your login view
# If you already have a login view, decorate it. Example below:

from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@ip_rate_limit(methods=['POST'])
def login_view(request):
    """
    Your existing login logic here.
    This is an example stub — replace with your actual login view code.
    """
    if request.method != "POST":
        return JsonResponse({"detail": "POST only"}, status=405)

    # existing login logic (authenticate, token creation, etc.)
    # For demonstration:
    return JsonResponse({"detail": "login attempt received"})
