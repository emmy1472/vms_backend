from rest_framework import viewsets, status # type: ignore
from rest_framework.response import Response # type: ignore
from rest_framework.permissions import IsAuthenticated # type: ignore
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
        user = serializer.save()

        try:
            sent_count = send_mail(
                subject="Welcome to NETCO Visitor Management System",
                message=f"Hi {user.username}, your account has been created Pasword: Welcome$. Please log in and change your password.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            print(f"send_mail returned: {sent_count}")  # Debug: check if email was sent
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
        # Admin sees all employees
        return User.objects.filter(role='employee')


class EmployeeProfileViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Employee views their own profile
    """
    serializer_class = EmployeeProfileSerializer
    permission_classes = [IsAuthenticated]  # <-- Change to allow any authenticated user

    def get_queryset(self):
        # Only return profile for the logged-in employee
        return EmployeeProfile.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['post'])
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
            {"detail": "Password changed successfully."},
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
        Returns the username of the currently authenticated user.
        """
        user = request.user
        if not user or not user.is_authenticated:
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({"username": user.username})

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

        serial = serializer.validated_data['serial_number']
        img = qrcode.make(serial)
        buffer = BytesIO()
        img.save(buffer)
        qr_image = ContentFile(buffer.getvalue(), f'{serial}.png')

        # Set owner manually from validated data or foreign key
        employee = serializer.validated_data.get('owner')
        if not employee:
            raise ValidationError("Device must be linked to an employee.")

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
        
        # Create guest object with token
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

        # Send email to guest with QR code attached
        if guest.email:
            email = EmailMessage(
                subject="You're Invited to NETCO",
                body=f"Dear {guest.full_name},\n\nYou have been invited to visit NETCO.\n"
                     f"Please find your visit token QR code attached.\n\nThank you.",
                from_email="emmanuelakinmolayan1@gmail.com",
                to=[guest.email],
            )
            email.attach(f'{guest.token}.png', buffer.getvalue(), 'image/png')
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
        return AccessLog.objects.all()
