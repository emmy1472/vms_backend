from django.contrib import admin
from .models import Device

# Register your models here.

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ['device_name', 'owner_employee', 'owner_guest',  'serial_number', 'qr_code', 'is_verified']
    search_fields = ['device_name', 'serial_number']
    list_filter = ['is_verified']