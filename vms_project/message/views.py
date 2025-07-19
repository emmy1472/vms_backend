from .serializers import MessageSerializer
from rest_framework import viewsets # type: ignore
from .models import Message
from rest_framework.permissions import IsAuthenticated # type: ignore
from rest_framework.response import Response # type: ignore
from rest_framework.views import APIView # type: ignore
from vms_app.permissions import IsAdminOrReadOnly, IsAdmin

# Create your views here.


# Message board for employees and admins
class MessageViewSet(viewsets.ModelViewSet):
    queryset = Message.objects.all().order_by("-created_at")
    serializer_class = MessageSerializer
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(sender=self.request.user)

    def get_queryset(self):
        return Message.objects.all().order_by("-created_at")
    
# Admin table for messages
class AdminMessagesAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        messages = Message.objects.all().order_by("-created_at")
        data = [
            {
                "id": m.id,
                "sender_username": getattr(m.sender, "username", None),
                "content": m.content,
                "created_at": m.created_at,
            } for m in messages
        ]
        return Response(data)