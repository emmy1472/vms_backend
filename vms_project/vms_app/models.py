from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
import qrcode
from io import BytesIO
from django.core.files import File
from PIL import Image  # type: ignore
from .generate import generate_short_token

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



    

class EmployeeProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    position = models.CharField(max_length=100)
    staff_id = models.CharField(max_length=50, unique=True)
    id_qr_code = models.ImageField(upload_to='qr_codes/', blank=True)
    date_registered = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.get_full_name() or self.user.username

    def save(self, *args, **kwargs):
        if not self.id_qr_code:
            qr = qrcode.make(self.staff_id)
            buffer = BytesIO()
            qr.save(buffer)
            self.id_qr_code.save(f"{self.staff_id}_qr.png", File(buffer), save=False)
        super().save(*args, **kwargs)

class Device(models.Model):
    owner_employee = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE, null=True, blank=True)
    owner_guest = models.ForeignKey('Guest', on_delete=models.CASCADE, null=True, blank=True)
    device_name = models.CharField(max_length=100)
    serial_number = models.CharField(max_length=100, unique=True)
    qr_code = models.ImageField(upload_to='qr_codes/', blank=True)
    date_registered = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.device_name

    def save(self, *args, **kwargs):
        if not self.qr_code:
            qr = qrcode.make(self.serial_number)
            buffer = BytesIO()
            qr.save(buffer)
            self.qr_code.save(f"{self.serial_number}_qr.png", File(buffer), save=False)
        super().save(*args, **kwargs)




class Guest(models.Model):
    full_name = models.CharField(max_length=100)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=15)
    purpose = models.TextField()
    invited_by = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)
    token = models.CharField(
        max_length=10,
        unique=True,
        editable=False,
        default=generate_short_token
    )
    token_qr_code = models.ImageField(upload_to='qr_codes/', blank=True)
    is_verified = models.BooleanField(default=False)
    visit_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.token_qr_code:
            qr = qrcode.make(str(self.token))
            buffer = BytesIO()
            qr.save(buffer)
            self.token_qr_code.save(f"{self.full_name}_token_qr.png", File(buffer), save=False)
        super().save(*args, **kwargs)



class AccessLog(models.Model):
    PERSON_TYPE_CHOICES = (
        ('employee', 'Employee'),
        ('guest', 'Guest'),
    )
    person_type = models.CharField(max_length=10, choices=PERSON_TYPE_CHOICES)
    person_id = models.PositiveIntegerField()
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    person = GenericForeignKey('content_type', 'person_id')
    device_serial = models.CharField(max_length=100)
    scanned_by = models.ForeignKey('vms_app.User', on_delete=models.SET_NULL, null=True, limit_choices_to={'role': 'security'})
    time_in = models.DateTimeField(auto_now_add=True)
    time_out = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=(('in', 'In'), ('out', 'Out')))
