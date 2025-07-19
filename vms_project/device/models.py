from django.db import models
from employee.models import EmployeeProfile





# Create your models here.


class Device(models.Model):
    owner_employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE, null=True, blank=True)
    owner_guest = models.ForeignKey('guest.Guest', on_delete=models.CASCADE, null=True, blank=True)
    device_name = models.CharField(max_length=100)
    serial_number = models.CharField(max_length=100, unique=True)
    qr_code = models.URLField(blank=True)
    date_registered = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.device_name

    

    def get_full_info(self):
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

