# 🛡️ IP Tracking and Security Middleware — ALX Backend Security

This project implements layered IP-based security features in Django as part of the **ALX Backend Security** curriculum.  
It includes IP logging, blocking, geolocation analytics, rate limiting, and anomaly detection using Celery.

---

## 📂 Project Overview

**Repository:** `alx-backend-security`  
**App Directory:** `ip_tracking`  

This Django app enhances security visibility and control by tracking and responding to client IP behaviors.

---

## 🚀 Features Implemented

| Task | Feature | Description |
|------|----------|-------------|
| ✅ Task 0 | **Basic IP Logging Middleware** | Logs IP, timestamp, and path of every request |
| ✅ Task 1 | **IP Blacklisting** | Blocks requests from blacklisted IPs |
| ✅ Task 2 | **IP Geolocation Analytics** | Tracks user location (country, city) using geolocation API |
| ✅ Task 3 | **Rate Limiting by IP** | Prevents request abuse with per-IP limits |
| ✅ Task 4 | **Anomaly Detection (Celery Task)** | Flags suspicious IPs based on abnormal activity |

---

## 🧩 Project Structure

alx-backend-security/
│
├── ip_tracking/
│ ├── init.py
│ ├── middleware.py
│ ├── models.py
│ ├── views.py
│ ├── tasks.py
│ ├── management/
│ │ └── commands/
│ │ └── block_ip.py
│ └── migrations/
│
├── settings.py
├── requirements.txt
└── README.md

yaml
Copy code

---

## 🛠️ Installation & Setup

### 1️⃣ Clone Repository
```bash
git clone https://github.com/<your-username>/alx-backend-security.git
cd alx-backend-security
2️⃣ Create Virtual Environment
bash
Copy code
python3 -m venv venv
source venv/bin/activate
3️⃣ Install Dependencies
bash
Copy code
pip install -r requirements.txt
4️⃣ Apply Migrations
bash
Copy code
python manage.py makemigrations
python manage.py migrate
5️⃣ Run Development Server
bash
Copy code
python manage.py runserver
⚙️ Tasks Breakdown
🧱 Task 0 — Basic IP Logging Middleware
Objective: Log every incoming request’s IP, timestamp, and path.

Example (ip_tracking/middleware.py):

python
Copy code
from .models import RequestLog
from django.utils import timezone

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        path = request.path
        RequestLog.objects.create(ip_address=ip, timestamp=timezone.now(), path=path)
        return self.get_response(request)
Model (models.py):

python
Copy code
from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.ip_address} - {self.path}"
Register middleware in settings.py:

python
Copy code
MIDDLEWARE = [
    ...,
    'ip_tracking.middleware.IPLoggingMiddleware',
]
🚫 Task 1 — IP Blacklisting
Objective: Block blacklisted IPs via middleware.

Model:

python
Copy code
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
Middleware update:

python
Copy code
if BlockedIP.objects.filter(ip_address=ip).exists():
    return HttpResponseForbidden("Your IP has been blocked.")
Command (block_ip.py):

python
Copy code
from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Block a specific IP address'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str)

    def handle(self, *args, **options):
        BlockedIP.objects.get_or_create(ip_address=options['ip_address'])
        self.stdout.write(self.style.SUCCESS(f"Blocked IP: {options['ip_address']}"))
🌍 Task 2 — IP Geolocation Analytics
Objective: Add country and city to request logs using django-ipgeolocation.

Installation:

bash
Copy code
pip install django-ipgeolocation
Extended model:

python
Copy code
class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
Middleware update:

python
Copy code
from ipgeolocation import geolocate

geo = geolocate(ip)
RequestLog.objects.create(
    ip_address=ip, path=request.path, 
    country=geo.get('country_name'), city=geo.get('city')
)
⏱️ Task 3 — Rate Limiting by IP
Objective: Limit requests per minute by authentication state.

Installation:

bash
Copy code
pip install django-ratelimit
View (views.py):

python
Copy code
from django_ratelimit.decorators import ratelimit
from django.http import JsonResponse

@ratelimit(key='ip', rate='10/m', method='GET', block=True)
def protected_view(request):
    return JsonResponse({'message': 'Success'})
Configure in settings.py:

python
Copy code
RATELIMIT_ENABLE = True
⚠️ Task 4 — Anomaly Detection (Celery)
Objective: Detect and flag suspicious IP activity.

Celery task (tasks.py):

python
Copy code
from celery import shared_task
from .models import RequestLog, SuspiciousIP
from django.utils import timezone
from datetime import timedelta

@shared_task
def detect_anomalies():
    one_hour_ago = timezone.now() - timedelta(hours=1)
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    for ip in logs.values_list('ip_address', flat=True).distinct():
        count = logs.filter(ip_address=ip).count()
        if count > 100 or logs.filter(ip_address=ip, path__in=['/admin', '/login']).exists():
            SuspiciousIP.objects.get_or_create(ip_address=ip, reason='Excessive or sensitive access')
Model (models.py):

python
Copy code
class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    flagged_at = models.DateTimeField(auto_now_add=True)
Run Celery:

bash
Copy code
celery -A alx_backend_security worker -B --loglevel=info
🧪 Testing
To verify rate limiting, run:

bash
Copy code
curl http://127.0.0.1:8000/login -I
After 10 requests in a minute (authenticated), the server should return:

nginx
Copy code
HTTP 429 Too Many Requests
📜 License
This project is part of the ALX Software Engineering Program.
You are free to use and extend this implementation for learning purposes.

👨‍💻 Author
Ufuoma Ogedegbe
🔗 GitHub: @ufuos# 🛡️ IP Tracking and Security Middleware — ALX Backend Security

This project implements layered IP-based security features in Django as part of the **ALX Backend Security** curriculum.  
It includes IP logging, blocking, geolocation analytics, rate limiting, and anomaly detection using Celery.

---

## 📂 Project Overview

**Repository:** `alx-backend-security`  
**App Directory:** `ip_tracking`  

This Django app enhances security visibility and control by tracking and responding to client IP behaviors.

---

## 🚀 Features Implemented

| Task | Feature | Description |
|------|----------|-------------|
| ✅ Task 0 | **Basic IP Logging Middleware** | Logs IP, timestamp, and path of every request |
| ✅ Task 1 | **IP Blacklisting** | Blocks requests from blacklisted IPs |
| ✅ Task 2 | **IP Geolocation Analytics** | Tracks user location (country, city) using geolocation API |
| ✅ Task 3 | **Rate Limiting by IP** | Prevents request abuse with per-IP limits |
| ✅ Task 4 | **Anomaly Detection (Celery Task)** | Flags suspicious IPs based on abnormal activity |

---

## 🧩 Project Structure

alx-backend-security/
│
├── ip_tracking/
│ ├── init.py
│ ├── middleware.py
│ ├── models.py
│ ├── views.py
│ ├── tasks.py
│ ├── management/
│ │ └── commands/
│ │ └── block_ip.py
│ └── migrations/
│
├── settings.py
├── requirements.txt
└── README.md

yaml
Copy code

---

## 🛠️ Installation & Setup

### 1️⃣ Clone Repository
```bash
git clone https://github.com/<your-username>/alx-backend-security.git
cd alx-backend-security
2️⃣ Create Virtual Environment
bash
Copy code
python3 -m venv venv
source venv/bin/activate
3️⃣ Install Dependencies
bash
Copy code
pip install -r requirements.txt
4️⃣ Apply Migrations
bash
Copy code
python manage.py makemigrations
python manage.py migrate
5️⃣ Run Development Server
bash
Copy code
python manage.py runserver
⚙️ Tasks Breakdown
🧱 Task 0 — Basic IP Logging Middleware
Objective: Log every incoming request’s IP, timestamp, and path.

Example (ip_tracking/middleware.py):

python
Copy code
from .models import RequestLog
from django.utils import timezone

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        path = request.path
        RequestLog.objects.create(ip_address=ip, timestamp=timezone.now(), path=path)
        return self.get_response(request)
Model (models.py):

python
Copy code
from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.ip_address} - {self.path}"
Register middleware in settings.py:

python
Copy code
MIDDLEWARE = [
    ...,
    'ip_tracking.middleware.IPLoggingMiddleware',
]
🚫 Task 1 — IP Blacklisting
Objective: Block blacklisted IPs via middleware.

Model:

python
Copy code
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
Middleware update:

python
Copy code
if BlockedIP.objects.filter(ip_address=ip).exists():
    return HttpResponseForbidden("Your IP has been blocked.")
Command (block_ip.py):

python
Copy code
from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Block a specific IP address'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str)

    def handle(self, *args, **options):
        BlockedIP.objects.get_or_create(ip_address=options['ip_address'])
        self.stdout.write(self.style.SUCCESS(f"Blocked IP: {options['ip_address']}"))
🌍 Task 2 — IP Geolocation Analytics
Objective: Add country and city to request logs using django-ipgeolocation.

Installation:

bash
Copy code
pip install django-ipgeolocation
Extended model:

python
Copy code
class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
Middleware update:

python
Copy code
from ipgeolocation import geolocate

geo = geolocate(ip)
RequestLog.objects.create(
    ip_address=ip, path=request.path, 
    country=geo.get('country_name'), city=geo.get('city')
)
⏱️ Task 3 — Rate Limiting by IP
Objective: Limit requests per minute by authentication state.

Installation:

bash
Copy code
pip install django-ratelimit
View (views.py):

python
Copy code
from django_ratelimit.decorators import ratelimit
from django.http import JsonResponse

@ratelimit(key='ip', rate='10/m', method='GET', block=True)
def protected_view(request):
    return JsonResponse({'message': 'Success'})
Configure in settings.py:

python
Copy code
RATELIMIT_ENABLE = True
⚠️ Task 4 — Anomaly Detection (Celery)
Objective: Detect and flag suspicious IP activity.

Celery task (tasks.py):

python
Copy code
from celery import shared_task
from .models import RequestLog, SuspiciousIP
from django.utils import timezone
from datetime import timedelta

@shared_task
def detect_anomalies():
    one_hour_ago = timezone.now() - timedelta(hours=1)
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    for ip in logs.values_list('ip_address', flat=True).distinct():
        count = logs.filter(ip_address=ip).count()
        if count > 100 or logs.filter(ip_address=ip, path__in=['/admin', '/login']).exists():
            SuspiciousIP.objects.get_or_create(ip_address=ip, reason='Excessive or sensitive access')
Model (models.py):

python
Copy code
class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    flagged_at = models.DateTimeField(auto_now_add=True)
Run Celery:

bash
Copy code
celery -A alx_backend_security worker -B --loglevel=info
🧪 Testing
To verify rate limiting, run:

bash
Copy code
curl http://127.0.0.1:8000/login -I
After 10 requests in a minute (authenticated), the server should return:

nginx
Copy code
HTTP 429 Too Many Requests
📜 License
This project is part of the ALX Software Engineering Program.
You are free to use and extend this implementation for learning purposes.

👨‍💻 Author
Ufuoma Ogedegbe
🔗 GitHub: @ufuos