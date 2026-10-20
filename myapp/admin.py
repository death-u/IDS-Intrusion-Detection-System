from django.contrib import admin
from .models import IntrusionLog, UserProfile

admin.site.register(IntrusionLog)
admin.site.register(UserProfile)