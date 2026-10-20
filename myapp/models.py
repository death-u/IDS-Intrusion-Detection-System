from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Useful for IDS logging 
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    is_locked = models.BooleanField(default=False)

class IntrusionLog(models.Model):
    ATTACK_TYPES = [
        ('sqli', 'SQL Injection'),
        ('xss', 'Cross-Site Scripting'),
        ('path_traversal', 'Path Traversal'),
        ('brute_force', 'Brute Force'),
    ]

    ip_address = models.GenericIPAddressField()
    attack_type = models.CharField(max_length=20, choices=ATTACK_TYPES)
    path = models.CharField(max_length=255)
    payload = models.TextField()  
    timestamp = models.DateTimeField(auto_now_add=True)
    blocked = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.attack_type} from {self.ip_address} at {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']


from django.utils import timezone

class LoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    email_attempted = models.CharField(max_length=255, blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

class IDSSettings(models.Model):
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"IDS {'Active' if self.is_active else 'Inactive'}"

    @classmethod
    def get_settings(cls):
        # Ensures only one settings row ever exists — creates it if missing
        settings_obj, created = cls.objects.get_or_create(id=1)
        return settings_obj