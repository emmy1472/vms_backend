from rest_framework import serializers  # Base class for all DRF serializers # type: ignore
from django.contrib.auth import get_user_model  # For referencing the custom user model
from .models import User  # Importing the custom User model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer  # JWT serializer for login # type: ignore

# Custom serializer to add extra fields to the JWT token
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom fields to the token payload (available in backend, not exposed to frontend)
        token['username'] = user.username
        token['role'] = user.role
        token['must_change_password'] = user.must_change_password
        token['reset_otp'] = getattr(user, 'reset_otp', None)

        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        # Include additional user data in the login response (accessible by frontend)
        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'role': self.user.role,
            'must_change_password': self.user.must_change_password,
            'reset_otp': getattr(self.user, 'reset_otp', None),
        }

        return data


# Reference to the custom user model for serialization
User = get_user_model()

# Basic user serializer (used in admin views or profile views)
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'role',
            'is_active',
            'must_change_password',
            'reset_otp'
        ]
