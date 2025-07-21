# Standard and third-party imports
import logging
import qrcode
from io import BytesIO

# Django core imports
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import BadHeaderError, send_mail
from django.utils.crypto import get_random_string
from django.conf import settings
from django.contrib.contenttypes.models import ContentType

# SMTP error handling
from smtplib import SMTPException

# Django REST Framework
from rest_framework import viewsets, status  # type: ignore
from rest_framework.response import Response  # type: ignore
from rest_framework.decorators import action  # type: ignore
from rest_framework.permissions import IsAuthenticated, AllowAny  # type: ignore
from rest_framework.views import APIView # type: ignore

# Cloudinary for image uploads
import cloudinary.uploader  # type: ignore

# App-specific imports
from .serializers import RegisterEmployeeSerializer, EmployeeProfileSerializer
from .models import EmployeeProfile
from vms_app.models import User
from vms_app.permissions import IsAdmin, IsAdminOrEmployee
from device.models import Device
from guest.models import Guest
from access_log.models import AccessLog

# Logger setup
logger = logging.getLogger(__name__)


class EmployeeViewSet(viewsets.ModelViewSet):
    """
    This view allows an Admin to manage employee user accounts.
    Actions: list, retrieve, create, update, destroy
    """

    queryset = User.objects.filter(role="employee")
    serializer_class = RegisterEmployeeSerializer
    permission_classes = [IsAuthenticated, IsAdmin]


class EmployeeProfileViewSet(viewsets.ModelViewSet):
    """
    This view manages employee profile data and custom endpoints.
    """

    serializer_class = EmployeeProfileSerializer
    permission_classes = [IsAuthenticated, IsAdminOrEmployee]

    def get_queryset(self):
        """
        Only allow the authenticated employee to access their profile.
        """
        user = self.request.user
        if hasattr(user, "role") and user.role == "employee":
            return EmployeeProfile.objects.filter(user=user)
        return EmployeeProfile.objects.none()

    @action(detail=False, methods=["get", "post"], url_path="me")
    def me(self, request):
        """
        GET: Returns the employee's profile with user info, picture, and QR code.
        POST: Allows employee to upload/update their profile picture.
        """
        user = request.user
        if not user or not user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Admins get a minimal response
        if not hasattr(user, "role") or user.role != "employee":
            return Response({
                "id": None,
                "username": user.username,
                "role": getattr(user, "role", None),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                },
                "profile_picture_url": None,
                "id_qr_code_url": None,
            })

        try:
            profile = EmployeeProfile.objects.get(user=user)

            # POST — Upload profile picture to Cloudinary
            if request.method == "POST":
                profile_picture = request.FILES.get("profile_picture")
                if not profile_picture:
                    return Response(
                        {"detail": "No profile_picture file provided."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                result = cloudinary.uploader.upload(
                    profile_picture,
                    folder="vms_app/profile_pictures",
                    public_id=f"{user.id}_profile",
                    overwrite=True,
                    resource_type="image",
                )
                profile.profile_picture = result["secure_url"]
                profile.save()

                return Response({
                    "detail": "Profile picture updated successfully.",
                    "profile_picture_url": result["secure_url"],
                }, status=status.HTTP_200_OK)

            # Generate and upload QR code if not already done
            if not profile.id_qr_code and profile.staff_id:
                qr = qrcode.make(profile.staff_id)
                buffer = BytesIO()
                qr.save(buffer, format="PNG")
                buffer.seek(0)
                qr_upload = cloudinary.uploader.upload(
                    buffer,
                    folder="vms_app/qr_codes",
                    public_id=f"qr_codes/{profile.staff_id}_qr",
                    overwrite=True,
                    resource_type="image",
                )
                profile.id_qr_code = qr_upload["secure_url"]
                profile.save()

            # Return profile info
            return Response({
                "id": profile.id,
                "username": user.username,
                "role": getattr(user, "role", None),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                },
                "profile_picture_url": profile.profile_picture,
                "id_qr_code_url": profile.id_qr_code,
            })

        except EmployeeProfile.DoesNotExist:
            return Response(
                {"detail": "Employee profile not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=False, methods=["get"], url_path="prompt_change")
    def get_must_change_password(self, request):
        """
        Checks if the user must change their password.
        """
        user = request.user
        must_change = bool(getattr(user, "must_change_password", False))
        return Response({"must_change_password": must_change})

    @action(detail=False, methods=["post"], url_path="change_password")
    def change_password(self, request):
        """
        Allows employee or admin to change their password securely.
        """
        user = request.user
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not new_password or not confirm_password:
            return Response(
                {"detail": "Both password fields are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if new_password != confirm_password:
            return Response(
                {"detail": "Passwords do not match."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            return Response({"detail": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.must_change_password = False
        user.save()

        return Response({
            "detail": "Password changed successfully.",
            "must_change_password": False
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="scan-qr")
    def scan_qr(self, request):
        """
        Returns full employee profile info based on staff_id from a scanned QR code.
        """
        staff_id = request.data.get("staff_id")
        if not staff_id:
            return Response(
                {"detail": "staff_id is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            profile = EmployeeProfile.objects.get(staff_id=staff_id)
            return Response(profile.get_full_info())
        except EmployeeProfile.DoesNotExist:
            return Response(
                {"detail": "EmployeeProfile not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=False, methods=["get"], url_path="dashboard")
    def dashboard(self, request):
        """
        Returns profile summary with device, guest, and attendance statistics.
        """
        try:
            profile = EmployeeProfile.objects.get(user=request.user)
        except EmployeeProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        from django.contrib.contenttypes.models import ContentType

        employee_type = ContentType.objects.get_for_model(profile)
        access_logs = AccessLog.objects.filter(
            content_type=employee_type,
            person_id=profile.id
        )
        devices = Device.objects.filter(owner_employee=profile)
        guests = Guest.objects.filter(invited_by=profile)

        data = profile.get_full_info()
        data.update({
            "device_count": devices.count(),
            "devices": [d.get_full_info() for d in devices],
            "guest_count": guests.count(),
            "attendance_in": access_logs.filter(status="in").count(),
            "attendance_out": access_logs.filter(status="out").count(),
        })

        return Response(data)

    @action(detail=False, methods=["get"], url_path="attendance")
    def attendance(self, request):
        """
        Returns a list of past attendance records for the employee.
        """
        try:
            profile = EmployeeProfile.objects.get(user=request.user)
        except EmployeeProfile.DoesNotExist:
            return Response(
                {"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND
            )

        

        logs = AccessLog.objects.filter(
            content_type=ContentType.objects.get_for_model(profile),
            person_id=profile.id
        ).order_by("-time_in")

        return Response([
            {
                "date": log.time_in.date() if log.time_in else None,
                "time_in": log.time_in.strftime("%H:%M:%S") if log.time_in else None,
                "time_out": log.time_out.strftime("%H:%M:%S") if log.time_out else None,
                "status": log.status,
            }
            for log in logs
        ])

    @action(detail=False, methods=["post"], url_path="forgot_password", permission_classes=[AllowAny])
    def forgot_password(self, request):
        """
        Sends a one-time OTP to the user's email for password reset.
        """
        email = request.data.get("email")
        if not email:
            return Response({"detail": "Email is required."}, status=400)

        user = get_user_model().objects.filter(email__iexact=email).first()
        if not user:
            return Response({"detail": "User with this email does not exist."}, status=404)

        otp = get_random_string(length=6, allowed_chars="0123456789")
        user.reset_otp = otp
        user.save()

        subject = "Password Reset OTP"
        message = f"Your OTP for password reset is: {otp}"
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None)

        if not from_email:
            return Response({"detail": "Server email configuration error."}, status=500)

        try:
            send_mail(subject, message, from_email, [email])
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return Response({"detail": "Failed to send email."}, status=500)

        return Response({"detail": "OTP sent to your email."}, status=200)

    @action(detail=False, methods=["post"], url_path="verify_otp", permission_classes=[AllowAny])
    def verify_otp(self, request):
        """
        Verifies if the provided OTP matches the one sent to the user's email.
        """
        email = request.data.get("email")
        otp = request.data.get("otp")

        if not email or not otp:
            return Response({"detail": "Email and OTP are required."}, status=400)

        try:
            user = get_user_model().objects.get(email=email)
            if user.reset_otp == otp:
                return Response({"detail": "OTP verified."}, status=200)
            return Response({"detail": "Invalid OTP."}, status=400)
        except get_user_model().DoesNotExist:
            return Response({"detail": "User not found."}, status=404)

    @action(detail=False, methods=["post"], url_path="reset_password", permission_classes=[AllowAny])
    def reset_password(self, request):
        """
        Resets a user's password after verifying the OTP.
        """
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        if not all([email, otp, new_password, confirm_password]):
            return Response({"detail": "All fields are required."}, status=400)

        if new_password != confirm_password:
            return Response({"detail": "Passwords do not match."}, status=400)

        try:
            user = get_user_model().objects.get(email=email)
            if user.reset_otp == otp:
                try:
                    validate_password(new_password, user=user)
                except ValidationError as e:
                    return Response({"detail": e.messages}, status=400)
                user.set_password(new_password)
                user.reset_otp = None
                user.save()
                return Response({"detail": "Password reset successful."}, status=200)
            return Response({"detail": "Invalid OTP."}, status=400)
        except get_user_model().DoesNotExist:
            return Response({"detail": "User not found."}, status=404)

# for admin view

class AdminEmployeesAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        employees = EmployeeProfile.objects.all().values(
            "id", "full_name", "department", "position", "staff_id"
        )
        return Response(list(employees))
    

# class SecurityEmployeesAPIView(APIView):
#     permission_classes = [IsAuthenticated, IsSecurity]

#     def get(self, request):
#         employees = EmployeeProfile.objects.all().values(
#             "id", "full_name", "department", "position", "staff_id"
#         )
#         return Response(list(employees))