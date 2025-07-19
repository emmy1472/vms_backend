# Import serializers and models
from .serializers import GuestSerializer
from .models import Guest

# Import permissions and REST framework utilities
from rest_framework.permissions import IsAuthenticated # type: ignore # Restrict access to authenticated users
from rest_framework import viewsets, status # type: ignore  # Base classes and HTTP status codes
from rest_framework.exceptions import PermissionDenied # type: ignore  # Exception for unauthorized access
from rest_framework.decorators import action # type: ignore # To create custom routes
from rest_framework.response import Response # type: ignore # Standard response object for views
from rest_framework.views import APIView  # type: ignore

# Django and third-party utilities
from django.db import transaction  # Ensure atomic DB operations
import qrcode  # Generate QR code for guest access token
from io import BytesIO  # In-memory file object for QR image
from employee.models import EmployeeProfile  # To link guest to inviting employee
from vms_app.permissions import IsAdmin # to restrict access to admin users
import cloudinary.uploader # type: ignore # Upload files to Cloudinary
from django.conf import settings  # Access project settings
from django.core.mail import EmailMessage  # Send email
from utils.sms import send_sms  # Custom utility to send SMS

# -----------------------------------------------------------------------------
# ViewSet for managing Guest records
# -----------------------------------------------------------------------------


class GuestViewSet(viewsets.ModelViewSet):
    """
    ViewSet for handling guest creation, listing, and QR code scanning.
    - Employees can invite guests (create guest records)
    - Security can view all guests
    """

    serializer_class = GuestSerializer
    permission_classes = [IsAuthenticated]  # Only authenticated users can use this API

    def perform_create(self, serializer):
        """
        Called automatically when a guest is created via POST /guests/
        - Only employees are allowed to invite guests.
        - A QR code is generated from the guest token.
        - QR is uploaded to Cloudinary and email/SMS is sent to the guest.
        """

        # Only users with the "employee" role can invite guests
        if self.request.user.role != "employee":
            raise PermissionDenied("Only employees can invite guests.")

        # Wrap the whole logic in a DB transaction (commit/rollback safety)
        with transaction.atomic():
            # Get the inviting employee's profile
            invited_by = EmployeeProfile.objects.get(user=self.request.user)

            # Save the guest with the `invited_by` field
            guest = serializer.save(invited_by=invited_by)

            # Generate a QR code from the guest's token
            qr_img = qrcode.make(str(guest.token))
            buffer = BytesIO()
            qr_img.save(buffer)  # Save the image to the buffer
            buffer.seek(0)  # Reset buffer pointer to the start

            # Upload QR code image to Cloudinary
            result = cloudinary.uploader.upload(
                buffer,
                folder="vms_app/guest_qr_codes",  # Cloudinary folder path
                public_id=f"guest_qr_{guest.token}",  # Unique file name
                overwrite=True,  # Replace if already exists
                resource_type="image",  # Type of media
            )

            # Save the QR code URL to the guest object
            guest.token_qr_code = result["secure_url"]
            guest.save()

            # App logo for email branding
            logo_url = settings.APP_LOGO_URL

            # If guest has an email address, send an invite email
            if guest.email:
                from django.template.loader import render_to_string

                # Render the HTML email with context data
                html_message = render_to_string(
                    "guest_invite_email.html",
                    {
                        "full_name": guest.full_name,
                        "app_name": "NETCO Visitor Management System",
                        "logo_url": logo_url,
                    },
                )

                # Build the actual email message
                email = EmailMessage(
                    subject="You're Invited to NETCO",
                    body=html_message,
                    from_email='"NETCO Visitor Management System" <{}>'.format(
                        settings.DEFAULT_FROM_EMAIL
                    ),
                    to=[guest.email],
                )
                email.content_subtype = "html"  # Set content to HTML

                # Attach the QR code image as PNG
                email.attach(f"{guest.token}.png", buffer.getvalue(), "image/png")

                # Send the email (fail_silently=False to raise error on failure)
                email.send(fail_silently=False)

                # Optional: Send SMS if guest provided a phone number
                if guest.phone:
                    try:
                        sms_message = (
                            f"Hello {guest.full_name}, you're invited to NETCO. "
                            f"Your access token is: {guest.token}"
                        )
                        send_sms(guest.phone, sms_message)
                    except Exception as e:
                        # Log or print SMS failure (but continue)
                        print(f"Failed to send SMS: {e}")

    def get_queryset(self):
        """
        Return guests based on user role:
        - Employees see only the guests they invited
        - Security sees all guests
        - Others see none
        """
        user = self.request.user

        if user.role == "employee":
            employee_profile = EmployeeProfile.objects.get(user=user)
            return Guest.objects.filter(invited_by=employee_profile)

        elif user.role == "security":
            return Guest.objects.all()

        else:
            return Guest.objects.none()

    @action(detail=False, methods=["post"], url_path="scan-qr")
    def scan_qr(self, request):
        """
        POST endpoint to scan guest QR code by token.
        Returns guest details if token is valid.
        """
        token = request.data.get("token")

        if not token:
            return Response(
                {"detail": "token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            guest = Guest.objects.get(token=token)
            return Response(guest.get_full_info())  # Custom method on model
        except Guest.DoesNotExist:
            return Response(
                {"detail": "Guest not found."},
                status=status.HTTP_404_NOT_FOUND,
            )


# for Administrator
class AdminGuestsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        guests = Guest.objects.all()
        data = []
        for g in guests:
            data.append(
                {
                    "id": g.id,
                    "full_name": g.full_name,
                    "phone": g.phone,
                    "purpose": g.purpose,
                    "invited_by_name": (
                        getattr(g.invited_by, "full_name", None)
                        if g.invited_by
                        else None
                    ),
                    "visit_date": g.visit_date,
                    "is_verified": g.is_verified,
                }
            )
        return Response(data)


# class SecurityGuestsAPIView(APIView):
#     permission_classes = [IsAuthenticated, IsSecurity]

#     def get(self, request):
#         guests = Guest.objects.all()
#         data = []
#         for g in guests:
#             data.append(
#                 {
#                     "id": g.id,
#                     "full_name": g.full_name,
#                     "phone": g.phone,
#                     "purpose": g.purpose,
#                     "invited_by_name": (
#                         getattr(g.invited_by, "full_name", None)
#                         if g.invited_by
#                         else None
#                     ),
#                     "visit_date": g.visit_date,
#                     "is_verified": g.is_verified,
#                 }
#             )
#         return Response(data)