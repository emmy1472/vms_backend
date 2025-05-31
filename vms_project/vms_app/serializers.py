from rest_framework import serializers # type: ignore
from django.contrib.auth import get_user_model
from .models import EmployeeProfile, Device, Guest, AccessLog
# serializers.py
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer # type: ignore

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claim (optional)
        token['username'] = user.username
        token['role'] = user.role
        token['must_change_password'] = user.must_change_password
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        # Add extra field to response
        data['must_change_password'] = self.user.must_change_password
        return data


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_active','must_change_password']


class RegisterEmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']  # No password field

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password="Welcome$",  # Always set default password
            role='employee'
        )



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





class AccessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessLog
        fields = ['id', 'person_type', 'person_id', 'device_serial', 'scanned_by', 'time_in', 'time_out', 'status']

# If your scan-qr endpoints are returning only the id, it's likely because your ViewSets are using ModelSerializers for responses.
# To return full info, update your scan_qr actions to return the output of get_full_info(), not the serializer.

# In your views.py, make sure you have:
# return Response(instance.get_full_info())
# instead of
# return Response(self.get_serializer(instance).data)
