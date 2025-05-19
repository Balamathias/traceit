from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission that allows only admins to edit, delete, or create objects.
    Everyone else can only read.
    """

    def has_permission(self, request, view):
        """Allow read-only methods (GET, HEAD, OPTIONS) for everyone"""
        if request.method in SAFE_METHODS:
            return True

        return request.user and request.user.is_staff
    

class IsOwnerOrReadOnly(BasePermission):
    """
    Only allow owners of a model to edit or delete it.
    Everyone else can only read.
    """
    def has_object_permission(self, request, view, obj) -> bool:
        """Read permissions for everyone"""
        if request.method in SAFE_METHODS:
            return True
        try:
            return obj.user == request.user
        except AttributeError:
            return obj.owner == request.user
        except Exception as e:
            print(f"Error in permission check: {e}")
            return False


class IsOwnerOnly(BasePermission):
    """
    Only allow owners of a model to edit or delete it.
    Everyone else can only read.
    """
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user
  