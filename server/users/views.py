"""
+++++++++++++++++++
An entry point into my views:

Views include:
* Token obtain views
* Restframework restful views
* SIMPLE JWT implementation or overriding views.

It is quite the ultimate file that makes it possible...
that makes it possible for clients to communicate with the legalX application.
+++++++++++++++++++++
"""

import time
import asyncio
import json
import os
from asgiref.sync import async_to_sync, sync_to_async
from django.http import StreamingHttpResponse
from django.db.models import Prefetch, Q

from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework import viewsets
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination

from django.shortcuts import get_object_or_404
from django.db.models import Count, Q
from django.db import models
from django.db.utils import IntegrityError
from django.utils import timezone

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken

from django.core.mail import EmailMultiAlternatives, send_mail
from django.conf import settings

from django_filters.rest_framework import DjangoFilterBackend, FilterSet
from rest_framework.filters import SearchFilter, OrderingFilter


from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string

from django.contrib.auth.signals import user_logged_in
from django.utils.timezone import now

from utils.constants import APP_NAME
from utils.response import ResponseMixin
from utils.emails import render_email_template
from utils.pagination import StackPagination

from users.serializers import RegisterSerializer, UserSerializer, TokenObtainPairSerializer, HelpRequestSerializer
from users.models import User
from users.permissions import (IsAdminOrReadOnly, IsOwnerOnly, IsOwnerOrReadOnly)


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def create(self, request, *args, **kwargs):
        try:
            email = request.data.get('email')
            if email and User.objects.filter(email=email).exists():
                response = dict(
                    status="Bad request",
                    message='Email already registered',
                    code=status.HTTP_400_BAD_REQUEST,
                    error={'email': ['This email address is already in use.']},
                    data=None
                )
                return Response(data=response, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)

            user.generate_otp()
            
            try:
                self.send_otp_email(user)
            except Exception as email_error:
                print(f"Error sending email: {email_error}")

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            response = dict(
                message="Registration successful. Please check your email for the OTP.",
                status="success",
                code=status.HTTP_201_CREATED,
                data=dict(
                    user=serializer.data,
                    access_token=access_token,
                    refresh_token=refresh_token,
                )
            )
            return Response(response, status=status.HTTP_201_CREATED, headers=headers)

        except ValidationError as e:
            print(e)
            errors = e.detail
            if 'email' in errors:
                message = 'Invalid email format or email already in use'
            else:
                message = 'Registration failed'
                
            response = dict(
                status="Bad request",
                message=message,
                code=status.HTTP_400_BAD_REQUEST,
                error=errors,
                data=None
            )
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)
        
        except IntegrityError as e:
            if 'email' in str(e).lower():
                response = dict(
                    status="Bad request",
                    message='Email already registered',
                    code=status.HTTP_400_BAD_REQUEST,
                    error={'email': ['This email address is already in use.']},
                    data=None
                )
            else:
                response = dict(
                    status="Bad request",
                    message='Registration failed due to data conflict',
                    code=status.HTTP_400_BAD_REQUEST,
                    error={'detail': str(e)},
                    data=None
                )
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            print(f"Too bad: ", e)
            user = User.objects.filter(email=request.data.get('email')).first()
            if user and (not user.is_active):
                try:
                    user.generate_otp()
                    self.send_otp_email(user)
                except Exception as resend_error:
                    print(f"Error resending OTP: {resend_error}")

                    response = dict(
                        status="Bad request",
                        message='Failed to resend OTP, please try again.',
                        code=status.HTTP_400_BAD_REQUEST,
                        error={'message': 'An error occurred while resending the OTP.', 'detail': str(resend_error)},
                        data=None
                    )
                    return Response(response, status=status.HTTP_400_BAD_REQUEST)
                
            response = dict(
                status="Bad request",
                message='Registration failed, please try again.',
                code=status.HTTP_400_BAD_REQUEST,
                error={'message': 'An error occurred while processing your request. Please try again.', 'detail': str(e)},
                data=None
            )
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        
    def perform_create(self, serializer):
        user = serializer.save()
        return user

    def send_otp_email(self, user):
        subject = f'{APP_NAME} - Your OTP for account verification'
        
        # Prepare context for the email template
        context = {
            'user_email': user.email,
            'otp': user.otp,
            'expiry_minutes': 15,
            'username': user.username or user.email.split('@')[0],
            'first_name': user.first_name,
            'last_name': user.last_name,
        }
        
        try:
            # Render the email template
            html_content, plain_text_content = render_email_template('otp_verification', context)
            
            # Create email message with both HTML and plain text versions
            email = EmailMultiAlternatives(
                subject,
                plain_text_content,
                settings.DEFAULT_FROM_EMAIL,
                [user.email]
            )
            email.attach_alternative(html_content, "text/html")
            email.send(fail_silently=False)
        except Exception as e:
            print(f"Error sending OTP email: {e}")
            # Depending on your error handling strategy, you might want to re-raise
            # or just log this error


class VerifyOTPView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        otp_input = request.data.get('otp')
        email = request.data.get('email')

        if not otp_input or not email:
            return Response(data={'message': 'OTP and email are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            if user.is_otp_valid(otp_input):
                user.is_active = True  # Activate the user
                user.otp = None  # Clear the OTP
                user.otp_created_at = None  # Clear OTP timestamp
                user.save()

                # Send welcome email after successful verification
                self.send_welcome_email(user)

                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                response = {
                    'message': 'OTP verified successfully. Account is now active.',
                    'access_token': access_token,
                    'refresh_token': refresh_token
                }

                return Response(data=response, status=status.HTTP_200_OK)

            else:
                return Response(data={'message': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response(data={'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    def send_welcome_email(self, user):
        subject = f'Welcome to {APP_NAME}!'

        context = {
            'username': user.username or user.email.split('@')[0],
            'first_name': user.first_name,
            'last_name': user.last_name,
            'account_url': f"{os.environ.get('FRONTEND_URL', 'https://lawstack.me')}/dashboard",
        }

        html_content, plain_text_content = render_email_template('welcome', context)

        email = EmailMultiAlternatives(
            subject,
            plain_text_content,
            settings.DEFAULT_FROM_EMAIL,
            [user.email]
        )
        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=False)


class ResendOTPView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        if not email:
            return Response({'message': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            if user.is_active:
                return Response({'message': 'User is already active.'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate and send new OTP
            user.generate_otp()
            self.send_otp_email(user)

            return Response({'message': 'OTP has been resent.'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        except ValueError as e:
            response = dict(
                status="Bad request",
                message='Wait for at least two minutes before requesting for a new code.',
                code=status.HTTP_400_BAD_REQUEST,
                error={ 'detail': str(e) },
                data=None
            )
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    def send_otp_email(self, user):
        subject = f'Your OTP for account verification for {APP_NAME}'
        
        context = {
            'user_email': user.email,
            'otp': user.otp,
            'expiry_minutes': 15,
            'username': user.username or user.email.split('@')[0],
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_resend': True,
        }
        
        html_content, plain_text_content = render_email_template('otp_verification', context)
        
        email = EmailMultiAlternatives(
            subject,
            plain_text_content,
            settings.DEFAULT_FROM_EMAIL,
            [user.email]
        )
        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=False)


class RequestPasswordResetView(APIView, ResponseMixin):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return self.response(error="Email is required.", message="Email is required.", status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return self.response(error="User not found.", message="No user with this email.", status=status.HTTP_404_NOT_FOUND)
        otp = default_token_generator.make_token(user)
        # Render robust HTML email template for OTP
        html_content = render_to_string(
            'emails/otp_verification.html',
            {
                'APP_NAME': getattr(settings, 'APP_NAME', 'ABU Law Clinic'),
                'first_name': user.first_name,
                'username': user.username,
                'otp': otp,
                'expiry_minutes': 15,
                'is_resend': False,
            }
        )
        send_mail(
            subject="Your ABU Law Clinic Password Reset OTP",
            message=f"Your OTP for password reset is: {otp}",
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
            recipient_list=[user.email],
            html_message=html_content,
        )
        return self.response(message="OTP sent to your email.", status=status.HTTP_200_OK)


class VerifyPasswordResetOTPView(APIView, ResponseMixin):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")
        if not (email and otp and new_password):
            return self.response(error="Missing fields.", message="Email, OTP, and new password are required.", status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return self.response(error="User not found.", message="No user with this email.", status=status.HTTP_404_NOT_FOUND)
        if not default_token_generator.check_token(user, otp):
            return self.response(error="Invalid OTP.", message="The OTP is invalid or expired.", status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()
        return self.response(message="Password reset successful.", status=status.HTTP_200_OK)


class ObtainTokenPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = TokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            try:
                username = request.data.get('username') or request.data.get('email', '')
                
                user = User.objects.filter(username=username).first() or User.objects.filter(email=username).first()
                
                if user:
                    
                    request.session.create()
                    request.user = user

                    user_logged_in.send(sender=user.__class__, request=request, user=user)

                    user.last_login = timezone.now()
                    user.save(update_fields=['last_login'])
                    
                    self.send_login_notification(user, request)
            except Exception as e:
                print(f"Error sending login notification: {e}")
        
        return response
    
    def send_login_notification(self, user, request):
        """Send an email notification about the new login"""
        # Extract device and browser info
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
        device = "Mobile" if 'Mobile' in user_agent else "Desktop"
        browser = self._get_browser_info(user_agent)
        
        # Get IP address and location
        ip_address = self._get_client_ip(request)
        location = self._get_location_from_ip(ip_address)
        
        # Prepare context for email template
        context = {
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'login_time': timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
            'device': device,
            'browser': browser,
            'location': location,
            'ip_address': ip_address,
            'security_url': f"{os.environ.get('FRONTEND_URL', 'https://lawstack.ai')}/dashboard/settings/security",
            'APP_NAME': APP_NAME
        }
        
        # Send email notification
        subject = f'New Login to Your {APP_NAME} Account'
        html_content, plain_text_content = render_email_template('login_notification', context)
        
        email = EmailMultiAlternatives(
            subject,
            plain_text_content,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            headers={'X-Use-Gmail': 'True'}
        )
        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=True)  # Use fail_silently=True to prevent login failures
    
    def _get_browser_info(self, user_agent):
        """Extract browser information from user agent"""
        if 'Chrome' in user_agent and 'Edg' not in user_agent:
            return 'Google Chrome'
        elif 'Firefox' in user_agent:
            return 'Mozilla Firefox'
        elif 'Safari' in user_agent and 'Chrome' not in user_agent:
            return 'Safari'
        elif 'Edg' in user_agent:
            return 'Microsoft Edge'
        elif 'MSIE' in user_agent or 'Trident/' in user_agent:
            return 'Internet Explorer'
        else:
            return 'Unknown Browser'
    
    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'Unknown')
        return ip
    
    def _get_location_from_ip(self, ip_address):
        """Get approximate location from IP address"""
        try:
            # This is a placeholder. For production, you would use a geolocation service
            # For now, return a generic response
            # return "Unknown location"
            
            # Example implementation with a geolocation service:
            import requests
            response = requests.get(f"https://ipapi.co/{ip_address}/json/")
            data = response.json()
            if response.status_code == 200:
                city = data.get('city', 'Unknown city')
                region = data.get('region', 'Unknown region')
                country = data.get('country_name', 'Unknown country')
                return f"{city}, {region}, {country}"
            return "Unknown location"
        except Exception:
            return "Unknown location"


class RefreshTokenView(TokenRefreshView):
    permission_classes = (AllowAny,)


class UpdateUserView(APIView, ResponseMixin):
    permission_classes = [IsAuthenticated]

    def put(self, request):

        user = request.user
        data = request.data

        try:

            user.first_name = data.get("first_name", user.first_name)
            user.last_name = data.get("last_name", user.last_name)
            user.avatar = data.get("avatar", user.avatar)
            user.username = data.get("username", user.username)
            user.phone = data.get("phone", user.phone)

            user.save()

            serializer = UserSerializer(user)
            return self.response(data=serializer.data, message="User updated successfully")
        
        except User.DoesNotExist:
            return self.response(data=None, message="User not found", status=status.HTTP_404_NOT_FOUND)
        
        except ValidationError as e:
            return self.response(data=None, message="Validation error", status=status.HTTP_400_BAD_REQUEST, error=e.detail)
        
        except IntegrityError as e:
            return self.response(data=None, message=f"Username - {data.get('username')} already exists", status=status.HTTP_400_BAD_REQUEST, error={"username": "Username already exists", 'detail': str(e)})
        
        except Exception as e:
            return self.response(data=None, message="An error occurred", status=status.HTTP_500_INTERNAL_SERVER_ERROR, error={"detail": str(e)})


class CurrentUserView(APIView, ResponseMixin):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return self.response(data=serializer.data, message="User retrieved successfully")
    

class LogoutView(APIView, ResponseMixin):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")

            token = RefreshToken(refresh_token)
            token.blacklist()

            return self.response(data={"message": "Logout successful"}, message="Logout successful", status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return self.response(data={"message": "Bad request"}, message="Bad request", status=status.HTTP_400_BAD_REQUEST)
        

class UserViewSet(ModelViewSet, ResponseMixin):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminOrReadOnly]
    lookup_field = "id"

    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["username", "first_name", "last_name", "email", "phone",]
    search_fields = ["username", "first_name", "last_name", "email", "phone",]
    ordering_fields = ["username", "first_name", "last_name", "email", "phone",]
    ordering = ["-username", 'email']

    pagination_class = StackPagination

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        paginated_queryset = self.paginate_queryset(queryset)
        if paginated_queryset is not None:
            serializer = self.get_serializer(paginated_queryset, many=True)
            paginated_data = self.get_paginated_response(serializer.data).data  

            return Response({
                "count": paginated_data["count"],
                "next": paginated_data["next"],
                "previous": paginated_data["previous"],
                "data": paginated_data["results"],
                "message": "Users retrieved successfully",
                "status": 200,
                "error": None
            })

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "count": len(serializer.data),
            "next": None,
            "previous": None,
            "data": serializer.data,
            "message": "Users retrieved successfully",
            "status": 200,
            "error": None
        })
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return self.response(data=serializer.data, message="Users retrieved successfully")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return self.response(data=serializer.data, message="Users created successfully", status_code=status.HTTP_201_CREATED)
        return self.response(error=serializer.errors, message="Failed to create Users", status_code=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return self.response(data=serializer.data, message="Users updated successfully")
        return self.response(error=serializer.errors, message="Failed to update Users", status_code=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return self.response(message="Users deleted successfully", status_code=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'], permission_classes=[IsAdminUser])
    def overview(self, request):
        """
        Returns statistics about users in the system.
        Only accessible to admin users.
        """
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        staff_users = User.objects.filter(is_staff=True).count()
        admin_users = User.objects.filter(is_superuser=True).count()
        
        stats = {
            'totalUsers': total_users,
            'activeUsers': active_users,
            'staffUsers': staff_users,
            'adminUsers': admin_users
        }
        
        return self.response(
            data=stats,
            message="User overview statistics retrieved successfully"
        )

