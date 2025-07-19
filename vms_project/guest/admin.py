from django.contrib import admin
from .models import Guest

# Register your models here.


@admin.register(Guest)
class GuestAdmin(admin.ModelAdmin):
    list_display = ['full_name', 'phone', 'purpose', 'invited_by', 'token', 'visit_date', 'is_verified', ]
    search_fields = ['full_name', 'phone']
    list_filter = ['is_verified', 'visit_date']