from rest_framework import viewsets  # Base viewset class # type: ignore
from rest_framework.permissions import IsAuthenticated  # Ensures user is authenticated # type: ignore
from rest_framework.response import Response  # Used to send JSON responses # type: ignore
from rest_framework.views import APIView  # For custom API views # type: ignore
from django.utils.timezone import now  # Handles time zone aware datetime 
from django.contrib.contenttypes.models import ContentType  # Used for generic relations

from .serializers import AccessLogSerializer
from .models import AccessLog
from vms_app.permissions import IsEmployeeOrSecurityOrAdmin, IsSecurity, IsAdmin
from employee.models import EmployeeProfile
from device.models import Device
from guest.models import Guest


# Handles full CRUD for access logs.
class AccessLogViewSet(viewsets.ModelViewSet):
    serializer_class = AccessLogSerializer
    permission_classes = [IsAuthenticated, IsEmployeeOrSecurityOrAdmin]

    def get_queryset(self):
        user = self.request.user

        if user.role == "employee":
            # Employee sees only their logs
            return AccessLog.objects.filter(
                person_type="employee", person_id=user.employeeprofile.id
            )
        else:
            # Admins and security see all logs
            return AccessLog.objects.all()


# Security-specific viewset to list logs (currently customized GET only)
class SecurityAccessLogAPIView(APIView):

    permission_classes = [IsAuthenticated, IsSecurity]

    def get(self, request):
        logs = self.get_queryset().order_by("-time_in")
        data = []

        for l in logs:
            # Get person name based on type
            person_name = "Unknown"
            if hasattr(l.person, "full_name"):
                person_name = l.person.full_name

            device_serial = str(l.device) if l.device else "No Device"

            data.append({
                "id": l.id,
                "person_type": l.person_type,
                "person_id": l.person_id,
                "person_name": person_name,
                "device": device_serial,
                "scanned_by": getattr(l.scanned_by, "username", None) if l.scanned_by else None,
                "time_in": l.time_in,
                "time_out": l.time_out,
                "status": l.status,
            })

        return Response(data)


# Admin-only view for accessing all access logs
class AdminAccessLogsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        logs = AccessLog.objects.all().order_by("-time_in")
        data = []

        for l in logs:
            person_name = "Unknown"
            if hasattr(l.person, "full_name"):
                person_name = l.person.full_name

            device_serial = str(l.device) if l.device else "No Device"

            data.append({
                "id": l.id,
                "person_type": l.person_type,
                "person_id": l.person_id,
                "person_name": person_name,
                "device": device_serial,
                "scanned_by": getattr(l.scanned_by, "username", None) if l.scanned_by else None,
                "time_in": l.time_in,
                "time_out": l.time_out,
                "status": l.status,
            })

        return Response(data)


# Handles scanning logic: staff IDs, guest tokens, and device serials
class SecurityScanAPIView(APIView):
    permission_classes = [IsAuthenticated, IsSecurity]

    def post(self, request):
        qr_value = request.data.get("qr_value")
        device_serial = request.data.get("device_serial")
        action = request.data.get("action", "in")  # in or out

        if not qr_value:
            return Response({"detail": "qr_value is required."}, status=400)

        person_type = None
        person_obj = None
        person_info = {}
        device = None

        # Try to identify the person based on QR value
        try:
            # Try employee
            person_obj = EmployeeProfile.objects.get(staff_id=qr_value)
            person_type = "employee"
            person_info = person_obj.get_full_info()
        except EmployeeProfile.DoesNotExist:
            try:
                # Try guest
                guest = Guest.objects.get(token=qr_value)
                if guest.token_expiry and guest.token_expiry < now():
                    return Response({"detail": "Token has expired."}, status=403)
                person_obj = guest
                person_type = "guest"
                person_info = person_obj.get_full_info()
            except Guest.DoesNotExist:
                try:
                    # Try device
                    device = Device.objects.get(serial_number=qr_value)
                    return Response({"type": "device", "device": device.get_full_info()}, status=200)
                except Device.DoesNotExist:
                    return Response({"detail": "QR or token not found."}, status=404)

        # Match the device if provided
        if device_serial:
            try:
                device = Device.objects.get(serial_number=device_serial)
            except Device.DoesNotExist:
                return Response({"detail": "Device not found."}, status=404)

        # Log the access
        content_type = ContentType.objects.get_for_model(person_obj)
        log = AccessLog.objects.create(
            person_type=person_type,
            person_id=person_obj.id,
            content_type=content_type,
            device=device.serial_number if device else None,
            scanned_by=request.user,
            status=action,
        )

        return Response({
            "type": person_type,
            "person": person_info,
            "status": action,
            "device": device.get_full_info() if device else None,
            "log": "Attendance logged successfully.",
            "timestamp": log.time_in,
        }, status=200)
