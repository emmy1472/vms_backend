from rest_framework import serializers  # DRF serializers for model transformation # type: ignore
from .models import EmployeeProfile
from vms_app.models import User

# Serializer to register a new employee user (User model only)
class RegisterEmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']  # No password field exposed in the API

    def create(self, validated_data):
        """
        Automatically creates a new user with the role 'employee'.
        A default password 'Welcome$' is set.
        """
        return User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password="Welcome$",  # Default password (can be forced to reset later)
            role='employee'
        )


# Serializer for the EmployeeProfile model
class EmployeeProfileSerializer(serializers.ModelSerializer):
    # User is required as a reference (e.g., created with RegisterEmployeeSerializer)
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    # Optional profile picture upload
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = EmployeeProfile
        fields = [
            'id',
            'user',
            'full_name',
            'department',
            'position',
            'staff_id',
            'id_qr_code',         # QR code URL for ID badge
            'profile_picture',    # Profile picture URL or file
            'date_registered',    # Auto timestamp
        ]
        read_only_fields = ['id_qr_code', 'date_registered']
