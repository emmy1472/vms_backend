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



    

