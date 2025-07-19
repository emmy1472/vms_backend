from .serializers import AccessLogSerializer
from rest_framework import viewsets # type: ignore
from .models import AccessLog
from rest_framework.permissions import IsAuthenticated # type: ignore
from vms_app.permissions import IsEmployeeOrSecurityOrAdmin, IsSecurity, IsAdmin
from rest_framework.response import Response # type: ignore
from rest_framework.views import APIView # type: ignore


# Create your views here.


class AccessLogViewSet(viewsets.ModelViewSet):

    queryset = AccessLog.objects.all()
    serializer_class = AccessLogSerializer
    permission_classes = [IsAuthenticated, IsEmployeeOrSecurityOrAdmin]

    def get_queryset(self):
        user = self.request.user

        if user.role == "employee":
            # Return only this employee's logs
            return AccessLog.objects.filter(
                person_type="employee", person_id=user.employeeprofile.id
            )
        else:
            # Admin and security can see all logs
            return AccessLog.objects.all()


class SecurityAccessLogViewSet(viewsets.ModelViewSet):
    serializer_class = AccessLogSerializer
    queryset = AccessLog.objects.all()  # ✅ Add this
    permission_classes = [IsAuthenticated, IsSecurity]

    def get(self, request):
        logs = self.get_queryset().order_by("-time_in")
        data = []

        for l in logs:
            # Determine person name safely
            # Get person name safely
            person_name = "Unknown"
            if l.person_type == "employee":
                if hasattr(l.person, "full_name"):
                    person_name = l.person.full_name
            elif l.person_type == "guest":
                if hasattr(l.person, "full_name"):
                    person_name = l.person.full_name

            device_serial = str(l.device) if l.device else "No Device"

            data.append(
                {
                    "id": l.id,
                    "person_type": l.person_type,
                    "person_id": l.person_id,
                    "person_name": person_name,
                    "device": device_serial,
                    "scanned_by": (
                        getattr(l.scanned_by, "username", None)
                        if l.scanned_by
                        else None
                    ),
                    "time_in": l.time_in,
                    "time_out": l.time_out,
                    "status": l.status,
                }
            )

        return Response(data)
    
class AdminAccessLogsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        logs = AccessLog.objects.all().order_by("-time_in")
        data = []

        for l in logs:
            # Determine person name safely
            # Get person name safely
            person_name = "Unknown"
            if l.person_type == "employee":
                if hasattr(l.person, "full_name"):
                    person_name = l.person.full_name
            elif l.person_type == "guest":
                if hasattr(l.person, "full_name"):
                    person_name = l.person.full_name

            device_serial = str(l.device) if l.device else "No Device"

            data.append(
                {
                    "id": l.id,
                    "person_type": l.person_type,
                    "person_id": l.person_id,
                    "person_name": person_name,
                    "device": device_serial,
                    "scanned_by": (
                        getattr(l.scanned_by, "username", None)
                        if l.scanned_by
                        else None
                    ),
                    "time_in": l.time_in,
                    "time_out": l.time_out,
                    "status": l.status,
                }
            )

        return Response(data)