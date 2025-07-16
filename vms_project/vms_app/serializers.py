from rest_framework import serializers # type: ignore
from django.contrib.auth import get_user_model
from .models import EmployeeProfile, Device, Guest, AccessLog, Message
# serializers.py
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer # type: ignore





class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Custom JWT claims (for internal/backend use)
        token['username'] = user.username
        token['role'] = user.role
        token['must_change_password'] = user.must_change_password
        token['reset_otp'] = getattr(user, 'reset_otp', None)
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        # Return useful fields to frontend
        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'role': self.user.role,
            'must_change_password': self.user.must_change_password,
            'reset_otp': getattr(self.user, 'reset_otp', None),
        }

        return data



User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_active', 'must_change_password', 'reset_otp']


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
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = EmployeeProfile
        fields = [
            'id', 'user', 'full_name', 'department', 'position', 'staff_id',
            'id_qr_code', 'profile_picture', 'date_registered'
        ]


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

class GuestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Guest
        fields = ['id', 'full_name', 'email', 'phone', 'purpose', 'invited_by', 'token', 'token_qr_code', 'is_verified', 'visit_date', 'created_at']
        read_only_fields = ['token', 'token_qr_code', 'is_verified', 'created_at']




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
    
    def get_device(self, obj):
        return str(obj.device) if obj.device else "No Device"

class MessageSerializer(serializers.ModelSerializer):
    sender_username = serializers.CharField(source="sender.username", read_only=True)

    class Meta:
        model = Message
        fields = ["id", "sender", "sender_username", "content", "created_at"]
        read_only_fields = ["id", "sender", "sender_username", "created_at"]

# If your scan-qr endpoints are returning only the id, it's likely because your ViewSets are using ModelSerializers for responses.
# To return full info, update your scan_qr actions to return the output of get_full_info(), not the serializer.

# In your views.py, make sure you have:
# return Response(instance.get_full_info())
# instead of
# return Response(self.get_serializer(instance).data)
