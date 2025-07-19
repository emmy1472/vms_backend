from django.db import models
from django.contrib.auth.models import AbstractUser






class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('employee', 'Employee'),
        ('security', 'Security'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='employee')
    is_active = models.BooleanField(default=True)
    must_change_password = models.BooleanField(default=True)
    email = models.EmailField(null=True)
    reset_otp = models.CharField(max_length=10, blank=True, null=True)  # For password reset OTP



    
class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    # Optionally, you can add a subject/title field
    # subject = models.CharField(max_length=255, blank=True)
    # For broadcast to all employees, no recipient FK needed

    def __str__(self):
        return f"Message from {self.sender.username} at {self.created_at}"
