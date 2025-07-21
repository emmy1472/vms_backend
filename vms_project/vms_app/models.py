from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Includes roles and additional fields for VMS requirements.
    """

    # Role-based access for different user types in the system
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('employee', 'Employee'),
        ('security', 'Security'),
    )

    # Defines what kind of user this is (admin, employee, or security)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='employee')

    # Controls if the user account is active (login allowed)
    is_active = models.BooleanField(default=True)

    # Forces the user to change their password after first login or reset
    must_change_password = models.BooleanField(default=True)

    # Optional email field (you can enforce this at registration)
    email = models.EmailField(null=True)

    # Stores OTP for password reset or verification flows
    reset_otp = models.CharField(max_length=10, blank=True, null=True)

    # __str__ is inherited from AbstractUser (usually returns the username)
