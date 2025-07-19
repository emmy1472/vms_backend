from rest_framework import serializers # type: ignore
from .models import Guest


class GuestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Guest
        fields = ['id', 'full_name', 'email', 'phone', 'purpose', 'invited_by', 'token', 'token_qr_code', 'is_verified', 'visit_date', 'created_at']
        read_only_fields = ['token', 'token_qr_code', 'is_verified', 'created_at']