from rest_framework import serializers # type: ignore
from .models import Message


class MessageSerializer(serializers.ModelSerializer):
    sender_username = serializers.CharField(source="sender.username", read_only=True)

    class Meta:
        model = Message
        fields = ["id", "sender", "sender_username", "content", "created_at"]
        read_only_fields = ["id", "sender", "sender_username", "created_at"]
