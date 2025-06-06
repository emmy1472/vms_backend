from rest_framework import viewsets, status # type: ignore
from rest_framework.response import Response # type: ignore
from rest_framework.permissions import IsAuthenticated, AllowAny # type: ignore
from django.contrib.auth import get_user_model
from .serializers import (
    RegisterEmployeeSerializer, EmployeeProfileSerializer, DeviceSerializer,
    GuestSerializer, AccessLogSerializer
)
from .models import EmployeeProfile, Device, Guest, AccessLog
from .permissions import IsAdmin, IsEmployee, IsSecurity
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
from rest_framework.decorators import action # type: ignore
from datetime import timedelta, datetime, timezone
from rest_framework.exceptions import PermissionDenied # type: ignore
from rest_framework_simplejwt.views import TokenObtainPairView # type: ignore
from .serializers import CustomTokenObtainPairSerializer
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMessage
from django.core.mail import send_mail, BadHeaderError
from smtplib import SMTPException
from rest_framework.decorators import api_view, permission_classes # type: ignore
from rest_framework.views import APIView # type: ignore
import os
from django.http import FileResponse, Http404
from django.utils.crypto import get_random_string




class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


User = get_user_model()


class EmployeeViewSet(viewsets.ModelViewSet):
    """
    Admin manages Employees: create/list/update/delete
    """
    queryset = User.objects.filter(role='employee')
    serializer_class = RegisterEmployeeSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def perform_create(self, serializer):
        # Set default password "Welcome$" for new users
        user = serializer.save(password="Welcome$")

        try:
            from django.template.loader import render_to_string
            from django.utils.html import strip_tags

            # Use your HTML template for the welcome email
            html_message = render_to_string(
                'welcome_email.html',
                {
                    'username': user.username,
                    'app_name': 'NETCO Visitor Management System',
                    'logo_url': 'https://a3a5-102-88-111-89.ngrok-free.app/static/logo.png',  # <-- Set to your public/static logo URL
                    'default_password': 'Welcome$',
                }
            )
            plain_message = strip_tags(html_message)

            email = EmailMessage(
                subject="Welcome to NETCO Visitor Management System",
                body=html_message,
                from_email='"NETCO Visitor Management System" <{}>'.format(settings.DEFAULT_FROM_EMAIL),
                to=[user.email],
            )
            email.content_subtype = "html"  # Send as HTML

            sent_count = email.send(fail_silently=False)
            print(f"send_mail returned: {sent_count}")
            if sent_count == 1:
                print("Email sent successfully!")
            else:
                print("Email was not sent.")
        except BadHeaderError:
            print("Invalid header found while sending email.")
            raise ValidationError({"detail": "Invalid header found while sending email."})
        except SMTPException as e:
            print(f"SMTP error occurred: {str(e)}")
            raise ValidationError({"detail": f"SMTP error occurred: {str(e)}"})
        except Exception as e:
            print(f"An error occurred while sending email: {str(e)}")
            raise ValidationError({"detail": f"An error occurred while sending email: {str(e)}"})

    def get_queryset(self):
        return User.objects.filter(role='employee')


class EmployeeProfileViewSet(viewsets.ModelViewSet):
    """
    Employee views and updates their own profile, including profile picture.
    """
    serializer_class = EmployeeProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return EmployeeProfile.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'], url_path='prompt_change')
    def get_must_change_password(self, request):
        """
        Returns must_change_password status for the current user.
        """
        user = request.user
        must_change = False
        if hasattr(user, 'must_change_password'):
            must_change = bool(getattr(user, 'must_change_password'))
        return Response({"must_change_password": must_change})

    @action(detail=False, methods=['post'], url_path='change_password')
    def change_password(self, request):
        # Ensure the same permission classes apply to this action
        self.check_permissions(request)

        user = request.user
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not new_password or not confirm_password:
            return Response(
                {"detail": "Both password fields are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if new_password != confirm_password:
            return Response(
                {"detail": "Passwords do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            return Response(
                {"detail": e.messages},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(new_password)
        if hasattr(user, 'must_change_password'):
            user.must_change_password = False  # Only if this field exists
        user.save()

        return Response(
            {"detail": "Password changed successfully.", "must_change_password": False},
            status=status.HTTP_200_OK
        )

    @action(detail=False, methods=['post'], url_path='scan-qr')
    def scan_qr(self, request):
        staff_id = request.data.get('staff_id')
        if not staff_id:
            return Response({"detail": "staff_id is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            profile = EmployeeProfile.objects.get(staff_id=staff_id)
            return Response(profile.get_full_info())  # <-- Ensure this line returns get_full_info()
        except EmployeeProfile.DoesNotExist:
            return Response({"detail": "EmployeeProfile not found."}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'], url_path='me')
    def me(self, request):
        """
        Returns the employee profile id, username, and role of the currently authenticated user.
        """
        user = request.user
        if not user or not user.is_authenticated:
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            profile = EmployeeProfile.objects.get(user=user)
            return Response({
                "id": profile.id,  # employee profile primary key
                "username": user.username,
                "role": getattr(user, "role", None),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
            })
        except EmployeeProfile.DoesNotExist:
            return Response({"detail": "Employee profile not found."}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'], url_path='dashboard')
    def dashboard(self, request):
        """
        Returns detailed info for the logged-in employee, including device count,
        guest count, and attendance (in/out) count.
        """
        try:
            profile = EmployeeProfile.objects.get(user=request.user)
        except EmployeeProfile.DoesNotExist:
            return Response({"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)

        # Devices
        devices = Device.objects.filter(owner_employee=profile)
        device_count = devices.count()

        # Guests invited
        guest_count = Guest.objects.filter(invited_by=profile).count()

        # Attendance logs (in/out)
        from django.contrib.contenttypes.models import ContentType
        employee_type = ContentType.objects.get_for_model(profile)
        access_logs = AccessLog.objects.filter(
            content_type=employee_type,
            person_id=profile.id
        )
        attendance_in = access_logs.filter(status='in').count()
        attendance_out = access_logs.filter(status='out').count()

        data = profile.get_full_info()
        data["device_count"] = device_count
        data["devices"] = [device.get_full_info() for device in devices]
        data["guest_count"] = guest_count
        data["attendance_in"] = attendance_in
        data["attendance_out"] = attendance_out

        return Response(data)

    @action(detail=True, methods=['get'], url_path='qr-code')
    def qr_code(self, request, pk=None):
        """
        Returns the QR code image for the employee profile.
        """
        try:
            profile = self.get_object()
            if not profile.id_qr_code:
                raise Http404("QR code not found.")
            return FileResponse(profile.id_qr_code.open('rb'), content_type='image/png')
        except Exception:
            raise Http404("QR code not found.")

    @action(detail=False, methods=['get'], url_path='qr-code')
    def my_qr_code(self, request):
        """
        Returns the QR code image for the currently authenticated employee.
        """
        try:
            profile = EmployeeProfile.objects.get(user=request.user)
            if not profile.id_qr_code:
                raise Http404("QR code not found.")
            return FileResponse(profile.id_qr_code.open('rb'), content_type='image/png')
        except EmployeeProfile.DoesNotExist:
            raise Http404("Profile not found.")
        except Exception:
            raise Http404("QR code not found.")

    @action(detail=False, methods=['get'], url_path='attendance')
    def attendance(self, request):
        """
        Returns a list of attendance logs for the logged-in employee.
        Each log contains date, time_in, time_out, and status.
        """
        try:
            profile = EmployeeProfile.objects.get(user=request.user)
        except EmployeeProfile.DoesNotExist:
            return Response({"detail": "Profile not found."}, status=status.HTTP_404_NOT_FOUND)

        from django.contrib.contenttypes.models import ContentType
        employee_type = ContentType.objects.get_for_model(profile)
        logs = AccessLog.objects.filter(
            content_type=employee_type,
            person_id=profile.id
        ).order_by('-time_in')

        data = []
        for log in logs:
            data.append({
                "date": log.time_in.date() if log.time_in else None,
                "time_in": log.time_in.strftime("%H:%M:%S") if log.time_in else None,
                "time_out": log.time_out.strftime("%H:%M:%S") if log.time_out else None,
                "status": log.status,
            })
        return Response(data)

    @action(detail=False, methods=['post'], url_path='forgot_password', permission_classes=[AllowAny])
    def forgot_password(self, request):
        """
        Sends a one-time password (OTP) to the user's email for password reset.
        """
        email = request.data.get('email')
        if not email:
            return Response({"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Use case-insensitive search for email
            user = get_user_model().objects.filter(email__iexact=email).first()
            if not user:
                return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
            otp = get_random_string(length=6, allowed_chars='0123456789')
            user.reset_otp = otp
            user.save()
            # Send OTP to email
            subject = "Password Reset OTP"
            message = f"Your OTP for password reset is: {otp}"
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
            return Response({"detail": "OTP sent to your email."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'], url_path='verify_otp', permission_classes=[AllowAny])
    def verify_otp(self, request):
        """
        Verifies the OTP sent to the user's email.
        """
        email = request.data.get('email')
        otp = request.data.get('otp')
        if not email or not otp:
            return Response({"detail": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = get_user_model().objects.get(email=email)
            if hasattr(user, 'reset_otp') and user.reset_otp == otp:
                return Response({"detail": "OTP verified."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except get_user_model().DoesNotExist:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['post'], url_path='reset_password', permission_classes=[AllowAny])
    def reset_password(self, request):
        """
        Resets the user's password after OTP verification.
        """
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        if not email or not otp or not new_password or not confirm_password:
            return Response({"detail": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != confirm_password:
            return Response({"detail": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = get_user_model().objects.get(email=email)
            if hasattr(user, 'reset_otp') and user.reset_otp == otp:
                try:
                    validate_password(new_password, user=user)
                except ValidationError as e:
                    return Response({"detail": e.messages}, status=status.HTTP_400_BAD_REQUEST)
                user.set_password(new_password)
                user.reset_otp = None
                user.save()
                return Response({"detail": "Password reset successful."}, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        except get_user_model().DoesNotExist:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

class DeviceViewSet(viewsets.ModelViewSet):
    """
    Security registers devices; Employees can view their own devices.
    """
    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'employee':
            return Device.objects.filter(owner__user=user)
        elif user.role == 'security':
            return Device.objects.all()
        else:
            return Device.objects.none()

    def perform_create(self, serializer):
        # Only security can register devices
        if self.request.user.role != 'security':
            raise PermissionDenied("Only security can register devices.")

        # Ensure 'owner' is present and validated by the serializer
        if 'owner' not in serializer.validated_data or not serializer.validated_data['owner']:
            raise ValidationError("Device must be linked to an employee.")

        serial = serializer.validated_data['serial_number']
        img = qrcode.make(serial)
        buffer = BytesIO()
        img.save(buffer)
        qr_image = ContentFile(buffer.getvalue(), f'{serial}.png')

        serializer.save(qr_code=qr_image)

    @action(detail=False, methods=['post'], url_path='scan-qr')
    def scan_qr(self, request):
        serial_number = request.data.get('serial_number')
        if not serial_number:
            return Response({"detail": "serial_number is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            device = Device.objects.get(serial_number=serial_number)
            return Response(device.get_full_info())  # <-- Ensure this line returns get_full_info()
        except Device.DoesNotExist:
            return Response({"detail": "Device not found."}, status=status.HTTP_404_NOT_FOUND)

class GuestViewSet(viewsets.ModelViewSet):
    """
    Employees invite guests (create), Security manages guest verification.
    """
    serializer_class = GuestSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        if self.request.user.role != 'employee':
            raise PermissionDenied("Only employees can invite guests.")

        invited_by = EmployeeProfile.objects.get(user=self.request.user)
        guest = serializer.save(invited_by=invited_by)

        # Generate QR code image from token
        qr_img = qrcode.make(str(guest.token))
        buffer = BytesIO()
        qr_img.save(buffer)
        buffer.seek(0)

        # Save QR to guest instance
        qr_file = ContentFile(buffer.getvalue(), f'{guest.token}.png')
        guest.token_qr_code.save(f'{guest.token}.png', qr_file)
        guest.save()

        # Get logo URL from settings for dynamic use
        logo_url = settings.APP_LOGO_URL

        # Send email to guest with QR code attached and inline
        if guest.email:
            from django.template.loader import render_to_string

            html_message = render_to_string(
                'guest_invite_email.html',
                {
                    'full_name': guest.full_name,
                    'app_name': 'NETCO Visitor Management System',
                    'logo_url': logo_url,
                }
            )

            email = EmailMessage(
                subject="You're Invited to NETCO",
                body=html_message,
                from_email='"NETCO Visitor Management System" <{}>'.format(settings.DEFAULT_FROM_EMAIL),
                to=[guest.email],
            )
            email.content_subtype = "html"

            # Attach QR code as an attachment (most reliable for all clients)
            email.attach(f'{guest.token}.png', buffer.getvalue(), 'image/png')
            # Inline display via Content-ID is not reliable across all clients, so attachment is preferred

            email.send(fail_silently=False)

    def get_queryset(self):
        user = self.request.user
        if user.role == 'employee':
            employee_profile = EmployeeProfile.objects.get(user=user)
            return Guest.objects.filter(invited_by=employee_profile)
        elif user.role == 'security':
            return Guest.objects.all()
        else:
            return Guest.objects.none()

    @action(detail=False, methods=['post'], url_path='scan-qr')
    def scan_qr(self, request):
        token = request.data.get('token')
        if not token:
            return Response({"detail": "token is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            guest = Guest.objects.get(token=token)
            return Response(guest.get_full_info())  # <-- Ensure this line returns get_full_info()
        except Guest.DoesNotExist:
            return Response({"detail": "Guest not found."}, status=status.HTTP_404_NOT_FOUND)




class AccessLogViewSet(viewsets.ModelViewSet):
    """
    Security logs access entries and exits.
    """
    serializer_class = AccessLogSerializer
    permission_classes = [IsAuthenticated, IsSecurity]

    def get_queryset(self):
        # For future: filter by user/date if needed for dashboards
        return AccessLog.objects.all()
