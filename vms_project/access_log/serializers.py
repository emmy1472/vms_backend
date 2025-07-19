from rest_framework import serializers # type: ignore
from .models import AccessLog


class AccessLogSerializer(serializers.ModelSerializer):
    person_name = serializers.SerializerMethodField()

    class Meta:
        model = AccessLog
        fields = ['id', 'person_type', 'person_id', 'person_name', 'device', 'scanned_by', 'time_in', 'time_out', 'status']

    def get_person_name(self, obj):
        if obj.person_type == "guest" and obj.person and hasattr(obj.person, "guest"):
            return obj.person.guest.full_name
        elif obj.person_type == "employee" and obj.person and hasattr(obj.person, "employeeprofile"):
            return obj.person.employeeprofile.full_name
        return "Unknown"
    
    # def get_device(self, obj):
    #     return str(obj.device.serial_number) if obj.device else "No Device"
