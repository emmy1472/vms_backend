from django.db import models
from employee.models import EmployeeProfile
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
import qrcode
from io import BytesIO
from vms_app.generate import generate_short_token
from django.utils import timezone
import cloudinary.uploader # type: ignore
from django.utils import timezone
from datetime import timedelta

# Create your models here.
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
    token_qr_code = models.URLField( blank=True)
    token_expiry = models.DateTimeField(default=timezone.now() + timedelta(hours=24))
    is_verified = models.BooleanField(default=False)
    visit_date = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.token_qr_code:
            qr = qrcode.make(str(self.token))
            buffer = BytesIO()
            qr.save(buffer)
            buffer.seek(0)

            result = cloudinary.uploader.upload(
                buffer,
                resource_type="image",
                public_id=f"qr_codes/{self.token}_qr",
                overwrite=True,
                folder="qr_codes"
            )

            self.token_qr_code = result['secure_url']

        super().save(*args, **kwargs)

    def __str__(self):
        return self.full_name  

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
            "token_qr_code_url": self.token_qr_code if self.token_qr_code else None,
            "is_verified": self.is_verified,
            "visit_date": self.visit_date,
            "created_at": self.created_at,
            "token_expired": self.is_token_expired(),
        }
