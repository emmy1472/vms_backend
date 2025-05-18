from rest_framework import viewsets, status # type: ignore
from rest_framework.response import Response # type: ignore
from rest_framework.permissions import IsAuthenticated # type: ignore
from django.contrib.auth import get_user_model
from .serializers import (
    RegisterEmployeeSerializer, EmployeeProfileSerializer, DeviceSerializer,
    GuestSerializer, GuestDeviceSerializer, AccessLogSerializer
)
from .models import EmployeeProfile, Device, Guest, AccessLog, GuestDevice
from .permissions import IsAdmin, IsEmployee, IsSecurity
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
from rest_framework.decorators import action # type: ignore
from datetime import timedelta, datetime, timezone
from rest_framework.exceptions import PermissionDenied # type: ignore

User = get_user_model()


class EmployeeViewSet(viewsets.ModelViewSet):
    """
    Admin manages Employees: create/list/update/delete
    """
    queryset = User.objects.filter(role='employee')
    serializer_class = RegisterEmployeeSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

    def get_queryset(self):
        # Admin sees all employees
        return User.objects.filter(role='employee')


class EmployeeProfileViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Employee views their own profile
    """
    serializer_class = EmployeeProfileSerializer
    permission_classes = [IsAuthenticated, IsEmployee]

    def get_queryset(self):
        # Only return profile for the logged-in employee
        return EmployeeProfile.objects.filter(user=self.request.user)


class DeviceViewSet(viewsets.ModelViewSet):
    """
    Employee registers devices; Security can list and verify devices.
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
        # Only employees can create devices
        if self.request.user.role != 'employee':
            return Response({"detail": "Only employees can register devices."},
                            status=status.HTTP_403_FORBIDDEN)

        serial = serializer.validated_data['serial_number']
        img = qrcode.make(serial)
        buffer = BytesIO()
        img.save(buffer)
        qr_image = ContentFile(buffer.getvalue(), f'{serial}.png')

        employee_profile = EmployeeProfile.objects.get(user=self.request.user)
        serializer.save(owner=employee_profile, qr_code=qr_image)


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
        # Create guest with token but DO NOT generate QR code here
        guest = serializer.save(invited_by=invited_by)
        guest.save()  # Just save without QR code

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated, IsSecurity])
    def verify_token(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"detail": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            guest = Guest.objects.get(token=token)
        except Guest.DoesNotExist:
            return Response({"detail": "Invalid token."}, status=status.HTTP_404_NOT_FOUND)

        now = datetime.now(timezone.utc)
        if guest.created_at < now - timedelta(hours=24):
            return Response({"detail": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)

        if guest.is_verified:
            return Response({"detail": "Guest already verified."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark guest as verified
        guest.is_verified = True

        # Generate QR code NOW and save
        qr_img = qrcode.make(str(guest.token))
        buffer = BytesIO()
        qr_img.save(buffer)
        qr_file = ContentFile(buffer.getvalue(), f'{guest.token}.png')
        guest.token_qr_code.save(f'{guest.token}.png', qr_file)
        guest.save()

        return Response({
            "detail": "Guest token verified and QR code generated successfully.",
            "guest_name": guest.full_name,
            "visit_date": guest.visit_date
        }, status=status.HTTP_200_OK)

    def get_queryset(self):
        user = self.request.user
        if user.role == 'employee':
            employee_profile = EmployeeProfile.objects.get(user=user)
            return Guest.objects.filter(invited_by=employee_profile)
        elif user.role == 'security':
            return Guest.objects.all()
        else:
            return Guest.objects.none()


class GuestDeviceViewSet(viewsets.ModelViewSet):
    """
    Security registers guest devices optionally.
    """
    serializer_class = GuestDeviceSerializer
    permission_classes = [IsAuthenticated, IsSecurity]

    def get_queryset(self):
        return GuestDevice.objects.all()


class AccessLogViewSet(viewsets.ModelViewSet):
    """
    Security logs access entries and exits.
    """
    serializer_class = AccessLogSerializer
    permission_classes = [IsAuthenticated, IsSecurity]

    def get_queryset(self):
        return AccessLog.objects.all()
