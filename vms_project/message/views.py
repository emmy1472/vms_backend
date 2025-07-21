from .serializers import MessageSerializer
from rest_framework import viewsets  # For creating class-based views with CRUD functionality # type: ignore
from .models import Message
from rest_framework.permissions import IsAuthenticated  # Ensures the user is logged in # type: ignore
from rest_framework.response import Response  # For returning HTTP responses # type: ignore
from rest_framework.views import APIView  # For more customized API views # type: ignore
from vms_app.permissions import IsAdminOrReadOnly, IsAdmin  # Custom permissions

# 📩 ViewSet for creating, listing, retrieving, updating, and deleting messages
# Used by both employees and admins
class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all().order_by("-created_at")  # Default queryset: latest messages first
    serializer_class = MessageSerializer  # Serializer to handle data validation and formatting
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]  # Only authenticated users can write; others can read

    # Automatically set the sender as the currently authenticated user when creating a message
    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

    # Override to always return messages ordered by most recent
    def get_queryset(self):
        return Message.objects.all().order_by("-created_at")

# 🛠 Admin-only API view for displaying messages in table format
class AdminMessagesAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Only admins can access this endpoint

    def get(self, request):
        # Get all messages sorted by most recent
        messages = Message.objects.all().order_by("-created_at")

        # Prepare simplified response data for admin table (no nested sender object)
        data = [
            {
                "id": m.id,
                "sender_username": getattr(m.sender, "username", None),
                "content": m.content,
                "created_at": m.created_at,
            }
            for m in messages
        ]
        return Response(data)
