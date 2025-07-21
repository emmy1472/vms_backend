from django.db import models
from employee.models import EmployeeProfile
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
import qrcode
from io import BytesIO
from vms_app.generate import generate_short_token
from django.utils import timezone
import cloudinary.uploader  # For uploading QR code images to Cloudinary # type: ignore
from datetime import timedelta

# Model to represent invited guests for employee visitations
class Guest(models.Model):
    full_name = models.CharField(max_length=100)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=15)
    purpose = models.TextField()  # Reason for the visit

    # The employee who invited the guest
    invited_by = models.ForeignKey(EmployeeProfile, on_delete=models.CASCADE)

    # Unique token assigned to each guest (used for QR and security verification)
    token = models.CharField(
        max_length=10,
        unique=True,
        editable=False,
        default=generate_short_token  # Automatically generates short unique token
    )

    # URL to the QR code image stored in Cloudinary
    token_qr_code = models.URLField(blank=True)

    # When the guest token will expire (default is 24 hours from creation)
    token_expiry = models.DateTimeField(default=timezone.now() + timedelta(hours=24))

    # Has the guest been verified at the gate?
    is_verified = models.BooleanField(default=False)

    # Scheduled date of the visit
    visit_date = models.DateField()

    # Record creation timestamp
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Auto-generate QR code only if it's not already set
        if not self.token_qr_code:
            qr = qrcode.make(str(self.token))
            buffer = BytesIO()
            qr.save(buffer)
            buffer.seek(0)

            # Upload QR image to Cloudinary
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
        """
        Checks if the guest token is expired.
        Tokens are valid only on the scheduled `visit_date`.
        """
        now = timezone.now().date()
        return now > self.visit_date

    def get_full_info(self):
        """
        Returns detailed info about the guest in dictionary format.
        Useful for API responses.
        """
        return {
            "id": self.id,
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "purpose": self.purpose,
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
