from rest_framework.permissions import BasePermission, SAFE_METHODS # type: ignore

class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'


class IsEmployee(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'employee'


class IsSecurity(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'security'


class IsOwnerOrAdmin(BasePermission):
    """
    Allow access to the owner of the object or an admin.
    """
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user or request.user.role == 'admin'
