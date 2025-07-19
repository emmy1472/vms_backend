from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import AdminGuestsAPIView, GuestViewSet

router = DefaultRouter()
router.register(r"guests", GuestViewSet, basename="guest")

urlpatterns = [
    path("", include(router.urls)),
    path('admin/guests/', AdminGuestsAPIView.as_view(), name='admin-guests'),
]