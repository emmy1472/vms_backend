from django.db import models
from vms_app.models import User
# Create your models here.


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    # Optionally, you can add a subject/title field
    # subject = models.CharField(max_length=255, blank=True)
    # For broadcast to all employees, no recipient FK needed

    def __str__(self):
        return f"Message from {self.sender.username} at {self.created_at}"