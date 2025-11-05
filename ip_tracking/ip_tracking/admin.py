# ip_tracking/admin.py
from django.contrib import admin
from .models import RequestLog

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'path', 'timestamp')
    list_filter = ('timestamp', 'ip_address')
    search_fields = ('ip_address', 'path')
    readonly_fields = ('ip_address', 'path', 'timestamp')
