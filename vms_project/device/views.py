# Import device serializer
from .serializers import DeviceSerializer

# Django REST framework imports
from rest_framework import viewsets, status  # type: ignore # ViewSet base class and status codes
from rest_framework.permissions import IsAuthenticated # type: ignore # Restrict access to authenticated users only
from rest_framework.exceptions import PermissionDenied # type: ignore # Raise error if user lacks required role
from rest_framework.response import Response # type: ignore # Used to return structured HTTP responses
from rest_framework.decorators import action # type: ignore # Allows creation of custom route methods
from rest_framework.views import APIView  # type: ignore 

# Model and utility imports
from .models import Device
import qrcode  # Library to generate QR codes
from io import BytesIO  # In-memory stream for image generation
from django.core.exceptions import ValidationError  # For custom validation errors
import cloudinary.uploader # type: ignore # Cloudinary for image uploads


from vms_app.permissions import IsAdmin, IsSecurity # to restrict other user only for admin
# -----------------------------------------------------------------------------
# DeviceViewSet: Handles creation and retrieval of registered devices
# -----------------------------------------------------------------------------


class DeviceViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing device registrations and retrieval.
    - Security can register devices.
    - Employees can view only the devices linked to them.
    """

    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated]  # Only authenticated users can use this API

    def get_queryset(self):
        """
        Return a queryset of devices owned by the currently authenticated employee.
        Security users will not receive any queryset here.
        """
        user = self.request.user
        return Device.objects.filter(owner_employee__user=user)

    def perform_create(self, serializer):
        """
        Handles the actual saving of a new device.
        - Only users with the role 'security' are allowed to register devices.
        - Generates a QR code based on the serial number.
        - Uploads the QR image to Cloudinary.
        - Saves the secure URL of the uploaded QR code to the device instance.
        """
        # Only security role is allowed to register devices
        if self.request.user.role != "security":
            raise PermissionDenied("Only security can register devices.")

        # Validate that the owner is provided in the request
        if (
            "owner" not in serializer.validated_data
            or not serializer.validated_data["owner"]
        ):
            raise ValidationError("Device must be linked to an employee.")

        # Extract serial number from validated data
        serial = serializer.validated_data["serial_number"]

        # Generate QR code from the serial number
        img = qrcode.make(serial)
        buffer = BytesIO()
        img.save(buffer, format="PNG")  # Save QR image as PNG
        buffer.seek(0)  # Move pointer back to start of buffer

        # Upload the QR code to Cloudinary
        result = cloudinary.uploader.upload(
            buffer,
            resource_type="image",
            public_id=f"vms_app/device_qr/{serial}_qr",  # Unique identifier in Cloudinary
            folder="vms_app/device_qr",  # Folder in Cloudinary
            overwrite=True,  # Overwrite existing file if exists
        )

        # Save the Cloudinary URL of the QR image with the device
        serializer.save(qr_code=result["secure_url"])

    @action(detail=False, methods=["post"], url_path="scan-qr")
    def scan_qr(self, request):
        """
        Custom endpoint to scan a device QR code by serial number.
        Returns full device information if found.
        """
        # Get the serial number from request body
        serial_number = request.data.get("serial_number")

        if not serial_number:
            return Response(
                {"detail": "serial_number is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Attempt to find device with matching serial number
            device = Device.objects.get(serial_number=serial_number)

            # Return full device details (should be implemented in the model)
            return Response(device.get_full_info())
        except Device.DoesNotExist:
            return Response(
                {"detail": "Device not found."}, status=status.HTTP_404_NOT_FOUND
            )


class AdminDevicesAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        devices = Device.objects.all()
        data = []
        for d in devices:
            data.append(
                {
                    "id": d.id,
                    "device_name": d.device_name,
                    "serial_number": d.serial_number,
                    "owner_employee_name": (
                        getattr(d.owner_employee, "full_name", None)
                        if d.owner_employee
                        else None
                    ),
                    "owner_guest_name": (
                        getattr(d.owner_guest, "full_name", None)
                        if d.owner_guest
                        else None
                    ),
                    "is_verified": d.is_verified,
                }
            )
        return Response(data)
    
    def perform_create(self, serializer):
        # Admin can register devices for employees or guests
        serial = serializer.validated_data["serial_number"]
        img = qrcode.make(serial)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(
            buffer, public_id=serial, folder="qr_codes"
        )

        # Save the Cloudinary URL in the qr_code field (make sure it's a URLField/ImageField)
        serializer.save(qr_code=upload_result["secure_url"])


class SecurityDeviceViewSet(viewsets.ModelViewSet):
    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated, IsSecurity]

    def get_queryset(self):
        return Device.objects.all()

    def get(self, request):
        devices = Device.objects.all()
        data = []
        for d in devices:
            data.append(
                {
                    "id": d.id,
                    "device_name": d.device_name,
                    "serial_number": d.serial_number,
                    "owner_employee_name": (
                        getattr(d.owner_employee, "full_name", None)
                        if d.owner_employee
                        else None
                    ),
                    "owner_guest_name": (
                        getattr(d.owner_guest, "full_name", None)
                        if d.owner_guest
                        else None
                    ),
                    "is_verified": d.is_verified,
                }
            )
        return Response(data)

    def perform_create(self, serializer):
        # Security can register devices for employees or guests
        serial = serializer.validated_data["serial_number"]
        img = qrcode.make(serial)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(
            buffer, public_id=serial, folder="qr_codes"
        )

        # Save the Cloudinary URL in the qr_code field (make sure it's a URLField/ImageField)
        serializer.save(qr_code=upload_result["secure_url"])

    @action(detail=False, methods=["post"], url_path="scan-qr")
    def scan_qr(self, request):
        serial_number = request.data.get("serial_number")
        if not serial_number:
            return Response(
                {"detail": "serial_number is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            device = Device.objects.get(serial_number=serial_number)
            return Response(device.get_full_info())
        except Device.DoesNotExist:
            return Response(
                {"detail": "Device not found."}, status=status.HTTP_404_NOT_FOUND
            )