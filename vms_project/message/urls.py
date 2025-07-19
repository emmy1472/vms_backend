from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import AdminMessagesAPIView, MessageViewSet


router = DefaultRouter()
router.register(r'messages', MessageViewSet, basename='message')

urlpatterns = [
    path('', include(router.urls)),
    path('admin/messages/', AdminMessagesAPIView.as_view(), name='admin-messages'),
]