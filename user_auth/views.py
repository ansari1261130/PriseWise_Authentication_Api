from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import get_object_or_404

from .models import User
from .renderers import UserRenderer
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserChangePasswordSerializer,
    UserResetPasswordSerializer,
    SendPasswordResetEmailSerializer
)


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({
            "message": "User registered successfully!",
            "token": token
        }, status=status.HTTP_201_CREATED)


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        login(request, user)  # Optional if you use session auth
        token = get_tokens_for_user(user)
        return Response({
            "message": "Login successful!",
            "token": token
        }, status=status.HTTP_200_OK)


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        # Password already set inside serializer validate
        return Response({"message": "Password changed successfully!"}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password reset link sent. Please check your email.'}, status=status.HTTP_200_OK)


class UserResetPasswordView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserResetPasswordSerializer(
            data=request.data,
            context={'uid': uid, 'token': token}
        )
        serializer.is_valid(raise_exception=True)
        # Serializer handles password reset and validation
        return Response({"message": "Password reset successfully!"}, status=status.HTTP_200_OK)


class UserLogoutView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        # If using JWT, add token blacklist logic here if needed
        return Response({"message": "Logout successful!"}, status=status.HTTP_200_OK)
