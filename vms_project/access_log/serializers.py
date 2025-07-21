from rest_framework import serializers  # Import Django REST Framework's serializer utilities # type: ignore
from .models import AccessLog  # Import the AccessLog model


# Serializer for AccessLog model
class AccessLogSerializer(serializers.ModelSerializer):
    # Custom field to dynamically return the person's name based on their type
    person_name = serializers.SerializerMethodField()

    class Meta:
        model = AccessLog  # This serializer is for the AccessLog model
        # Fields to include in the serialized output
        fields = [
            'id',
            'person_type',    # 'employee' or 'guest'
            'person_id',      # The ID of the related employee/guest
            'person_name',    # Computed name of the person
            'device',         # Serial number or reference to the device used
            'scanned_by',     # User who performed the scan
            'time_in',        # Timestamp of entry
            'time_out',       # Timestamp of exit
            'status'          # 'in' or 'out'
        ]

    # Method to compute and return the person's full name
    def get_person_name(self, obj):
        if obj.person_type == "guest" and obj.person and hasattr(obj.person, "guest"):
            return obj.person.guest.full_name  # Return guest's full name
        elif obj.person_type == "employee" and obj.person and hasattr(obj.person, "employeeprofile"):
            return obj.person.employeeprofile.full_name  # Return employee's full name
        return "Unknown"  # Fallback if not found

    # Optional: Custom logic for device name display (currently unused)
    # def get_device(self, obj):
    #     return str(obj.device.serial_number) if obj.device else "No Device"
