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

    def get_queryset(self):
        user = self.request.user
        if user.role == 'employee':
            employee_profile = EmployeeProfile.objects.get(user=user)
            return Guest.objects.filter(invited_by=employee_profile)
        elif user.role == 'security':
            return Guest.objects.all()
        else:
            return Guest.objects.none()

    def perform_create(self, serializer):
        if self.request.user.role != 'employee':
            return Response({"detail": "Only employees can invite guests."},
                            status=status.HTTP_403_FORBIDDEN)

        invited_by = EmployeeProfile.objects.get(user=self.request.user)
        guest = serializer.save(invited_by=invited_by)

        token = str(guest.token)
        img = qrcode.make(token)
        buffer = BytesIO()
        img.save(buffer)
        token_qr_image = ContentFile(buffer.getvalue(), f'{token}.png')
        guest.token_qr_code.save(f'{token}.png', token_qr_image)
        guest.save()


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
