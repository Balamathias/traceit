from django.urls import path

from django.urls import include

from rest_framework_simplejwt.views import TokenRefreshView

from rest_framework.routers import DefaultRouter

from users.views import (
    CurrentUserView,
    UserViewSet,
    LogoutView,
    ObtainTokenPairView,
    UpdateUserView,
    RegisterView,
    VerifyOTPView,
    ResendOTPView,
)

router = DefaultRouter()


router.register(r"users", UserViewSet, basename="users")

urlpatterns = [
    path('', include(router.urls)),
]

urlpatterns += [
    path('auth/login/', ObtainTokenPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),

    path('auth/user/', CurrentUserView.as_view(), name='current_user'),
    path('auth/update-user/', UpdateUserView.as_view(), name='update_user'),

    path('auth/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('auth/resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
]
