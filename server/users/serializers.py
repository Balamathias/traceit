from django.contrib.auth.password_validation import validate_password

from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer as DefaultTokenObtainPairSerializer
from rest_framework import serializers
from .models import (
    User, 
)


class TokenObtainPairSerializer(DefaultTokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['email'] = user.email

        return token

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
              required=True,
            #   validators=[UniqueValidator(queryset=User.objects.all())]
            )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    id = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'phone', 'password', 'avatar', 'metadata', 'username',)

    def validate(self, attrs):
        self.validate_username(attrs.get('username'))
        return attrs
    
    def get_id(self, obj):
        return obj.id
    
    def validate_email(self, email: str) -> str:
        """Validate a User's email
        - Is the email taken?
        - Does it contain the appropriate characters?

        Args:
            email (str): The email to validate

        Raises:
            serializers.ValidationError: Will scream and return a validation error.

        Returns:
            str: an affirmation that all went well
        """
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email is already taken")
        return email
    
    def validate_username(self, username: str) -> str:
        """Validate a User's username
        - Is the name taken?
        - Does it contain the appropriate characters?

        Args:
            username (str): The username to validate

        Raises:
            serializers.ValidationError: Will scream and return a validation error.

        Returns:
            str: an affirmation that all went well
        """
        if username and User.objects.filter(username=username).exists():
            raise serializers.ValidationError("Username is already taken")
        return username

    def create(self, validated_data):
        user: User = User.objects.create(
            **validated_data,
        )
        
        user.set_password(validated_data['password'])
        user.save()

        return user


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name', 'phone', 'avatar', 'metadata',
            'is_superuser', 'is_staff', 'is_active', 'date_joined', 'last_login'
        ]
        read_only_fields = ['is_superuser', 'is_staff', 'is_active']

    def create(self, validated_data):
        user: User = User.objects.create(**validated_data)
        return user
