from django.db import models


class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()  # Handles both IPv4 and IPv6
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    country = models.CharField(max_length=100, null=True, blank=True)  # For Task 2 (Geo info)
    city = models.CharField(max_length=100, null=True, blank=True)      # For Task 2 (Geo info)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
        ]
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"

    def __str__(self):
        return f"{self.ip_address} [{self.timestamp}] {self.path}"


class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField()
    reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.ip_address} - {self.reason[:60]}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
