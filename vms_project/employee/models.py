from django.db import models
from vms_app.models import User
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType



# Create your models here.


class EmployeeProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    position = models.CharField(max_length=100)
    staff_id = models.CharField(max_length=50, unique=True)
    id_qr_code = models.URLField(blank=True)
    profile_picture = models.URLField( blank=True, null=True)
    date_registered = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.get_full_name() or self.user.username
    
    def __str__(self):
        return self.full_name  

    

    def get_full_info(self):
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