from rest_framework import serializers # type: ignore
from django.contrib.auth import get_user_model
from .models import EmployeeProfile, Device, Guest, GuestDevice, AccessLog

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_active']


class RegisterEmployeeSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role='employee'
        )
        return user


class EmployeeProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = EmployeeProfile
        fields = ['id', 'user', 'full_name', 'department', 'position', 'staff_id', 'id_qr_code', 'date_registered']


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['id', 'owner', 'device_name', 'serial_number', 'qr_code', 'date_registered', 'is_verified']
        read_only_fields = ['qr_code', 'date_registered', 'is_verified']


class GuestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Guest
        fields = ['id', 'full_name', 'email', 'phone', 'purpose', 'invited_by', 'token', 'token_qr_code', 'is_verified', 'visit_date', 'created_at']
        read_only_fields = ['token', 'token_qr_code', 'is_verified', 'created_at']


class GuestDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = GuestDevice
        fields = ['id', 'guest', 'device_name', 'serial_number', 'qr_code', 'date_registered']
        read_only_fields = ['qr_code', 'date_registered']


class AccessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessLog
        fields = ['id', 'person_type', 'person_id', 'device_serial', 'scanned_by', 'time_in', 'time_out', 'status']
