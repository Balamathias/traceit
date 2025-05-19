# filepath: C:/Users/Mathias Bala/traceit/server/users/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import (
    ReadOnlyPasswordHashField,
    UserCreationForm as DjangoUserCreationForm,
    UserChangeForm as DjangoUserChangeForm,
)
from django import forms
from .models import User


class UserCreationForm(DjangoUserCreationForm):
    """Form for creating new users. Uses the same fields as your model + password confirmation."""
    class Meta:
        model = User
        fields = ("email", "first_name", "last_name", "username", "phone")

    def clean_password2(self):
        # DjangoUserCreationForm already does this, but just in case
        pw1 = self.cleaned_data.get("password1")
        pw2 = self.cleaned_data.get("password2")
        if pw1 and pw2 and pw1 != pw2:
            raise forms.ValidationError("Passwords don’t match")
        return pw2


class UserChangeForm(DjangoUserChangeForm):
    """Form for updating users. Replaces the password field with admin’s read-only display."""
    password = ReadOnlyPasswordHashField(label="Password",
        help_text=(
            "Raw passwords are not stored, so there is no way to see this user’s password, "
            "but you can change the password using "
            "<a href=\"../password/\">this form</a>."
        )
    )

    class Meta:
        model = User
        fields = [
            "email", "password", "first_name", "last_name", "username",
            "phone", "image", "metadata", "is_active", "is_staff",
            "is_superuser", "groups", "user_permissions",
            "otp", "otp_created_at", "last_login", "date_joined",
        ]


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    list_display = (
        "email", "first_name", "last_name", "username",
        "is_active", "is_staff", "is_superuser",
    )
    list_filter = ("is_staff", "is_superuser", "is_active", "date_joined")
    search_fields = ("email", "first_name", "last_name", "username")
    ordering = ("email",)
    filter_horizontal = ("groups", "user_permissions")

    # read-only on detail view
    readonly_fields = ("last_login", "date_joined", "otp_created_at")

    fieldsets = (
        (None, {
            "fields": (
                "email", "password",
            ),
        }),
        ("Personal info", {
            "fields": (
                "first_name", "last_name", "username", "phone", "image", "metadata"
            )
        }),
        ("Permissions", {
            "fields": (
                "is_active", "is_staff", "is_superuser", "groups", "user_permissions"
            )
        }),
        ("OTP / Security", {
            "fields": ("otp", "otp_created_at")
        }),
        ("Important dates", {
            "fields": ("last_login", "date_joined")
        }),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email", "first_name", "last_name", "username",
                "phone", "password1", "password2", "is_active", "is_staff", "is_superuser"
            ),
        }),
    )
