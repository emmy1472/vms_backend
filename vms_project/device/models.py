from django.db import models
from employee.models import EmployeeProfile
from guest.models import Guest

# Model to store registered devices for both employees and guests
class Device(models.Model):
    # ForeignKey to the employee who owns the device (optional)
    owner_employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE, null=True, blank=True)

    # ForeignKey to the guest who owns the device (optional)
    owner_guest = models.ForeignKey(Guest, on_delete=models.CASCADE, null=True, blank=True)

    # Name of the device (e.g., "iPhone 12")
    device_name = models.CharField(max_length=100)

    # Unique serial number of the device
    serial_number = models.CharField(max_length=100, unique=True)

    # URL to the QR code representing this device (can be empty until generated)
    qr_code = models.URLField(blank=True)

    # Timestamp of when the device was registered
    date_registered = models.DateTimeField(auto_now_add=True)

    # Flag to indicate if the device has been verified by security/admin
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        # String representation for debugging/admin display
        return self.device_name

    def get_full_info(self):
        """
        Returns a dictionary containing detailed info about the device,
        including owner details, QR code URL, and verification status.
        """
        return {
            "id": self.id,
            "owner_employee": self.owner_employee.get_full_info() if self.owner_employee else None,
            "owner_guest": self.owner_guest.get_full_info() if self.owner_guest else None,
            "device_name": self.device_name,
            "serial_number": self.serial_number,
            "qr_code_url": self.qr_code if self.qr_code else None,
            "date_registered": self.date_registered,
            "is_verified": self.is_verified,
        }
