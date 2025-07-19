from django.contrib import admin
from .models import AccessLog
# Register your models here.


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ['person_type', 'person_name', 'device', 'scanned_by', 'time_in', 'time_out', 'status']
    list_filter = ['status', 'person_type', 'time_in']

