from django.db import models
from vms_app.models import User

# Model to store additional profile details for employee users
class EmployeeProfile(models.Model):
    # One-to-one link to the user account (must be role="employee")
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    # Full name of the employee
    full_name = models.CharField(max_length=100)

    # Department the employee belongs to
    department = models.CharField(max_length=100)

    # Job position or title of the employee
    position = models.CharField(max_length=100)

    # Unique staff ID used to identify the employee (also used in QR codes)
    staff_id = models.CharField(max_length=50, unique=True)

    # URL to the staff ID QR code image
    id_qr_code = models.URLField(blank=True)

    # Optional profile picture URL
    profile_picture = models.URLField(blank=True, null=True)

    # Timestamp when the employee was registered
    date_registered = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """
        String representation of the employee, falling back to username if full_name is missing.
        """
        return self.full_name or self.user.get_full_name() or self.user.username

    def get_full_info(self):
        """
        Returns a dictionary with complete information about the employee and their linked user account.
        Useful for APIs or QR scanning responses.
        """
        return {
            "id": self.id,
            "user": {
                "id": self.user.id,
                "username": self.user.username,
                "email": self.user.email,
                "role": self.user.role,
                "is_active": self.user.is_active,
            },
            "full_name": self.full_name,
            "department": self.department,
            "position": self.position,
            "staff_id": self.staff_id,
            "id_qr_code_url": self.id_qr_code,
            "profile_picture_url": self.profile_picture if self.profile_picture else None,
            "date_registered": self.date_registered,
        }
