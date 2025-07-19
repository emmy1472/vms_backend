from django.contrib import admin
from .models import Message

# Register your models here.
@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'sender', 'content', 'created_at']
    search_fields = ['content', 'sender__username']
    list_filter = ['created_at']
