from rest_framework import serializers # type: ignore
from django.contrib.auth import get_user_model
from .models import User
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





