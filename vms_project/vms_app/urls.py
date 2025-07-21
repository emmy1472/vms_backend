from django.urls import path, include
from .views import (
    CreateEmployeeUserView,           # Admin creates a new employee user
    CustomTokenObtainPairView,       # Custom JWT login view
    AdminOverviewAPIView,            # Admin dashboard metrics
    AdminUsersAPIView,               # Admin view of all users
    user_me,                         # Returns current authenticated user info
    SecurityDashboardAPIView,        # Security dashboard metrics
)
from rest_framework_simplejwt.views import TokenRefreshView  # Endpoint for refreshing JWT token # type: ignore
from django.conf import settings
from django.conf.urls.static import static  # For serving static files during development


urlpatterns = [
    # JWT Auth Endpoints
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Login endpoint
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),       # Refresh token endpoint

    # Admin User Creation Endpoint
    path('users/', CreateEmployeeUserView.as_view(), name='create-user'),           # Admin creates a new user

    # Admin API Endpoints
    path('admin/overview/', AdminOverviewAPIView.as_view(), name='admin-overview'), # Admin metrics dashboard
    path('admin/users/', AdminUsersAPIView.as_view(), name='admin-users'),          # View all users

    # Endpoint for current authenticated user info
    path('users/me/', user_me, name='user-me'),                                      # Get current user info

    # Security Dashboard API Endpoint
    path('security/dashboard/', SecurityDashboardAPIView.as_view(), name='security-dashboard'),  # Security metrics
]

# Serve static files (e.g., logo) during development
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
