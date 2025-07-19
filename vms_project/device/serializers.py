from rest_framework import serializers # type: ignore
from .models import Device


class DeviceSerializer(serializers.ModelSerializer):
    # Remove or fix any reference to 'owner'
    # If you want to show the employee, use owner_employee and/or owner_guest

    class Meta:
        model = Device
        fields = [
            'id',
            'device_name',
            'serial_number',
            'qr_code',
            'date_registered',
            'is_verified',
            'owner_employee',  # FK to EmployeeProfile
            'owner_guest',     # FK to Guest (if needed)
            # Do NOT include 'owner'
        ]
        read_only_fields = ['qr_code', 'date_registered', 'is_verified']

    # Optionally, add a representation for owner_employee
    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.owner_employee:
            data['owner_employee_username'] = instance.owner_employee.user.username
        return data