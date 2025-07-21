from rest_framework import serializers  # Import DRF's serializers # type: ignore
from .models import Device  # Import the Device model


# Serializer for the Device model
class DeviceSerializer(serializers.ModelSerializer):
    # This serializer handles device data serialization/deserialization.
    # We're excluding the deprecated or removed `owner` field,
    # and using `owner_employee` and `owner_guest` instead.

    class Meta:
        model = Device  # Model being serialized
        fields = [
            'id',
            'device_name',
            'serial_number',
            'qr_code',
            'date_registered',
            'is_verified',
            'owner_employee',  # FK to EmployeeProfile
            'owner_guest',     # FK to Guest (optional use case)
        ]
        # Fields that should not be editable by the API consumer
        read_only_fields = ['qr_code', 'date_registered', 'is_verified']

    def to_representation(self, instance):
        """
        Optionally customize the output.
        Adds the employee's username if the device belongs to an employee.
        """
        data = super().to_representation(instance)
        if instance.owner_employee:
            data['owner_employee_username'] = instance.owner_employee.user.username
        return data
