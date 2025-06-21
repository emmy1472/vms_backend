from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
import qrcode
from io import BytesIO
from django.core.files import File
from PIL import Image  # type: ignore
from .generate import generate_short_token
from django.utils import timezone

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



    

class EmployeeProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    position = models.CharField(max_length=100)
    staff_id = models.CharField(max_length=50, unique=True)
    id_qr_code = models.ImageField(upload_to='qr_codes/', blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    date_registered = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.get_full_name() or self.user.username

    def save(self, *args, **kwargs):
    # Generate QR code if it doesn't exist
        if not self.id_qr_code:
            qr = qrcode.make(self.staff_id)
            buffer = BytesIO()
            qr.save(buffer)
            buffer.seek(0)
            self.id_qr_code.save(f"{self.staff_id}_qr.png", File(buffer), save=False)

    # Call the actual save method
        super().save(*args, **kwargs)

    # Resize profile picture if necessary
        if self.profile_picture:
            try:
                img = Image.open(self.profile_picture.path)
                if img.height > 400 or img.width > 400:
                    output_size = (400, 400)
                    img.thumbnail(output_size)
                    img.save(self.profile_picture.path)
            except Exception:
                pass  # Safely ignore if file not accessible or not an image


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
            "id_qr_code_url": self.id_qr_code.url if self.id_qr_code else None,
            "profile_picture_url": self.profile_picture.url if self.profile_picture else None,
            "date_registered": self.date_registered,
        }

    

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

    def get_full_info(self):
        return {
            "id": self.id,
            "owner_employee": self.owner_employee.get_full_info() if self.owner_employee else None,
            "owner_guest": self.owner_guest.get_full_info() if self.owner_guest else None,
            "device_name": self.device_name,
            "serial_number": self.serial_number,
            "qr_code_url": self.qr_code.url if self.qr_code else None,
            "date_registered": self.date_registered,
            "is_verified": self.is_verified,
        }




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
    token_expiry = models.DateTimeField(default=timezone.now)
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

    def is_token_expired(self):
        # Token expires 24 hours after visit_date (midnight to midnight)
        from django.utils import timezone
        now = timezone.now().date()
        return now > self.visit_date

    def get_full_info(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "purpose": self.purpose,
            # Avoid recursion: only include invited_by's basic info to prevent infinite nesting
            "invited_by": {
                "id": self.invited_by.id,
                "full_name": self.invited_by.full_name,
                "staff_id": self.invited_by.staff_id,
            } if self.invited_by else None,
            "token": self.token,
            "token_qr_code_url": self.token_qr_code.url if self.token_qr_code else None,
            "is_verified": self.is_verified,
            "visit_date": self.visit_date,
            "created_at": self.created_at,
            "token_expired": self.is_token_expired(),
        }



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

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    # Optionally, you can add a subject/title field
    # subject = models.CharField(max_length=255, blank=True)
    # For broadcast to all employees, no recipient FK needed

    def __str__(self):
        return f"Message from {self.sender.username} at {self.created_at}"
