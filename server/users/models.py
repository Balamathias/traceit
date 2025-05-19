import uuid
import datetime
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, AbstractUser
from django.utils import timezone
from django.conf import settings
from django.utils.timezone import now, timedelta


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")

        extra_fields.setdefault("is_active", True)
        user = self.model(email=self.normalize_email(email), **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)  # Ensure superusers are active by default

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    objects = UserManager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    phone = models.CharField(max_length=30, blank=True, null=True)
    username = models.CharField(max_length=40, blank=True, null=True, unique=True)
    image = models.ImageField(upload_to="profile_pics", blank=True, null=True)

    metadata = models.JSONField(default=dict, null=True, blank=True)
    date_joined = models.DateTimeField(auto_now_add=True)

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)

    last_login = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def generate_otp(self):
        """Generate a random 6-digit OTP if it doesn't exist or the cooldown period is over."""
        now = timezone.now()
        if not self.otp or (self.otp_created_at and now - self.otp_created_at >= datetime.timedelta(minutes=1)):
            self.otp = str(uuid.uuid4().int)[:6]
            self.otp_created_at = now
            self.save()
        else:
            raise ValueError("OTP was recently sent. Please wait a few minutes.")

    def is_otp_valid(self, otp_input):
        """Check if the provided OTP is valid and not expired."""
        if self.otp == otp_input and self.otp_created_at:
            expiry_time = self.otp_created_at + datetime.timedelta(minutes=15)
            return timezone.now() <= expiry_time
        return False

    def save(self, *args, **kwargs):
        # Handle password validation edge cases
        if hasattr(self, '_password') and self._password is None:
            self._password = ''
        
        super().save(*args, **kwargs)