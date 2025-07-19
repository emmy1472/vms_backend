from django.contrib import admin

# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Message
from .forms import CustomUserCreationForm




# Extend the default UserAdmin to show custom fields
class UserAdmin(BaseUserAdmin):
    add_form = CustomUserCreationForm

    fieldsets = BaseUserAdmin.fieldsets + (
        (None, {'fields': ('role', 'must_change_password')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'role', 'must_change_password'),  # Removed password1 and password2
        }),
    )

    list_display = ['username', 'email', 'role', 'is_active', 'is_staff', 'is_superuser', 'must_change_password']
    list_filter = ['role', 'is_active']
    search_fields = ['username', 'email']

    


# Register User using the custom admin
admin.site.register(User, UserAdmin)



@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'sender', 'content', 'created_at']
    search_fields = ['content', 'sender__username']
    list_filter = ['created_at']

