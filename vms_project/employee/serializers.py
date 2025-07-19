from rest_framework import serializers # type: ignore
from .models import EmployeeProfile
from vms_app.models import User



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
