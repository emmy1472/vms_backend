from django.contrib import admin
from .models import EmployeeProfile

# Register your models here.
@admin.register(EmployeeProfile)
class EmployeeProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'full_name', 'department', 'position', 'staff_id', 'id_qr_code', 'profile_picture', 'date_registered']
    search_fields = ['full_name', 'department', 'staff_id']