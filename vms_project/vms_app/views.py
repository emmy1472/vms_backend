from asyncio.log import logger
from datetime import datetime
import logging
from smtplib import SMTPException

# Django and DRF imports
from rest_framework import viewsets, generics  # View classes for API endpoints # type: ignore
from rest_framework.response import Response  # Used to return API responses # type: ignore
from rest_framework.decorators import api_view, permission_classes  # For function-based views # type: ignore
from rest_framework.permissions import IsAuthenticated  # Ensures only authenticated users can access # type: ignore
from rest_framework.views import APIView  # Base class for API views # type: ignore
from rest_framework_simplejwt.views import TokenObtainPairView  # For JWT auth # type: ignore

from django.contrib.auth import get_user_model  # Access the custom User model
from django.core.exceptions import ValidationError  # Raise validation errors
from django.core.mail import BadHeaderError, EmailMessage  # Email utilities
from django.conf import settings  # Access Django settings
from django.template.loader import render_to_string  # Render email templates
from django.utils.html import strip_tags  # Strip HTML from email for plain-text fallback

# Import serializers
from .serializers import CustomTokenObtainPairSerializer
from employee.serializers import RegisterEmployeeSerializer

# Import custom permissions and models
from .permissions import IsAdmin, IsSecurity
from message.models import Message
from guest.models import Guest
from employee.models import EmployeeProfile
from device.models import Device
from access_log.models import AccessLog

# Setup logger for this module
logger = logging.getLogger(__name__)

# Get the User model
User = get_user_model()

# ================================
# JWT AUTHENTICATION
# ================================

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token endpoint to include additional fields like role.
    """
    serializer_class = CustomTokenObtainPairSerializer


# ================================
# EMPLOYEE ACCOUNT CREATION (ADMIN)
# ================================

class CreateEmployeeUserView(generics.CreateAPIView):
    """
    API endpoint for admin to register a new employee user.
    Sends a welcome email after creation.
    """
    queryset = User.objects.all()
    serializer_class = RegisterEmployeeSerializer
    permission_classes = [IsAuthenticated]  # Optionally add IsAdmin for stricter access

    def perform_create(self, serializer):
        # Save new user with default password
        user = serializer.save(password="Welcome$")

        try:
            logo_url = settings.APP_LOGO_URL
            html_message = render_to_string("welcome_email.html", {
                "username": user.username,
                "app_name": "NETCO Visitor Management System",
                "logo_url": logo_url,
                "default_password": "Welcome$",
            })
            plain_message = strip_tags(html_message)

            email = EmailMessage(
                subject="Welcome to NETCO Visitor Management System",
                body=html_message,
                from_email=f'"NETCO Visitor Management System" <{settings.DEFAULT_FROM_EMAIL}>',
                to=[user.email],
            )
            email.content_subtype = "html"  # Send as HTML email
            email.send(fail_silently=False)

        except BadHeaderError:
            raise ValidationError({"detail": "Invalid header found while sending email."})
        except SMTPException as e:
            raise ValidationError({"detail": f"SMTP error occurred: {str(e)}"})
        except Exception as e:
            raise ValidationError({"detail": f"Unexpected error sending email: {str(e)}"})

    def get_queryset(self):
        # Return only employee users
        return User.objects.filter(role="employee")


# ================================
# ADMIN DASHBOARD OVERVIEW
# ================================

class AdminOverviewAPIView(APIView):
    """
    Returns total counts of all major models for dashboard stats.
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response({
            "users": User.objects.count(),
            "employees": EmployeeProfile.objects.count(),
            "devices": Device.objects.count(),
            "guests": Guest.objects.count(),
            "messages": Message.objects.count(),
            "access_logs": AccessLog.objects.count(),
        })


# ================================
# ADMIN: LIST USERS TABLE
# ================================

class AdminUsersAPIView(APIView):
    """
    Returns a list of all users (id, username, email, role, active status).
    """
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        users = User.objects.all().values("id", "username", "email", "role", "is_active")
        return Response(list(users))


# ================================
# CURRENTLY LOGGED IN USER
# ================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_me(request):
    """
    Returns details of the currently authenticated user.
    """
    user = request.user
    return Response({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": getattr(user, "role", None),
    })


# ================================
# SECURITY DASHBOARD OVERVIEW
# ================================

class SecurityDashboardAPIView(APIView):
    """
    Returns summary statistics for the security dashboard.
    """
    permission_classes = [IsAuthenticated, IsSecurity]

    def get(self, request):
        today = datetime.now().date()

        device_count = Device.objects.count()
        verified_device_count = Device.objects.filter(is_verified=True).count()
        guest_count = Guest.objects.count()
        guests_today = Guest.objects.filter(visit_date=today).count()
        expected_guests_today = Guest.objects.filter(visit_date=today, token_expiry__gte=datetime.now()).count()
        access_logs_today = AccessLog.objects.filter(time_in__date=today).count()

        return Response({
            "device_count": device_count,
            "verified_device_count": verified_device_count,
            "guest_count": guest_count,
            "guests_today": guests_today,
            "expected_guests_today": expected_guests_today,
            "access_logs_today": access_logs_today,
        })
