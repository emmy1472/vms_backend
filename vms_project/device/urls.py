from django.urls import path, include
from rest_framework.routers import DefaultRouter # type: ignore
from .views import AdminDevicesAPIView, DeviceViewSet, SecurityDeviceViewSet

router = DefaultRouter()
router.register(r"devices", DeviceViewSet, basename="device")


urlpatterns = [
    path("", include(router.urls)),
    path('admin/devices/', AdminDevicesAPIView.as_view(), name='admin-devices'),
    path('security/devices/', SecurityDeviceViewSet.as_view({'get': 'list'}), name='security-devices'),
]