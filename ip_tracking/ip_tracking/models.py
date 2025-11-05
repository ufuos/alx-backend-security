# ip_tracking/models.py
from django.db import models

class RequestLog(models.Model):
    ip_address = models.CharField(max_length=45)  # IPv6 length safe (45)
    timestamp = models.DateTimeField()
    path = models.CharField(max_length=500)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"

    def __str__(self):
        return f"{self.ip_address} - {self.path} @ {self.timestamp.isoformat()}"

        class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
