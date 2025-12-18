from rest_framework import generics, status
from django.contrib.auth.models import User
from user_auth_app.models import UserProfile
from .serializers import RegistrationSerializer, EmailAuthTokenSerializer
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response

import jwt
from django.conf import settings
from datetime import datetime, timedelta
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


class UserProfileList(generics.ListCreateAPIView):
    """
    API view to list all user profiles or create a new user profile.

    Inherits from Django REST Framework's ListCreateAPIView.
    Uses the RegistrationSerializer to serialize profile data.

    Methods:
        get(): Returns a list of all user profiles.
        post(): Creates a new user profile from request data.
    """
    queryset = UserProfile.objects.all()
    serializer_class = RegistrationSerializer


class UserProfileDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    API view to retrieve, update, or delete a specific user profile by ID.

    Inherits from RetrieveUpdateDestroyAPIView to provide full CRUD support
    for individual user profiles. Uses the RegistrationSerializer.

    Methods:
        get(): Retrieves a user profile by ID.
        put(): Updates a user profile by ID.
        delete(): Deletes a user profile by ID.
    """
    queryset = UserProfile.objects.all()
    serializer_class = RegistrationSerializer


class RegistrationView(APIView):
    """
    API view to register a new user and return authentication token.

    Accepts user data, creates a new user upon validation,
    and returns token and user details. Uses the RegistrationSerializer.

    Methods:
        post(): Handles user registration and token creation.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        data = {}

        if serializer.is_valid():
            saved_account = serializer.save()
            token, _ = Token.objects.get_or_create(user=saved_account)
            data = {
                # 'token': token.key,
                # 'username': f"{saved_account.first_name} {saved_account.last_name}".strip(),
                # 'email': saved_account.email,
                # 'user_id': saved_account.id
                'detail' : "User created successfully!"
            }
            return Response(data, status=status.HTTP_201_CREATED)
        else:
            data = serializer.errors
            return Response(data, status=status.HTTP_400_BAD_REQUEST)


class CustomLogInView(ObtainAuthToken):
    """
    API view for user login. Authenticates user and sets auth cookies.

    On success returns a JSON body with a detail message and user info,
    and sets `access_token` and `refresh_token` as HttpOnly cookies.
    """
    permission_classes = [AllowAny]
    serializer_class = EmailAuthTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data={
                'username': request.data.get('username'),
                'password': request.data.get('password')
            },
            context={'request': request}
        )

        try:
            if not serializer.is_valid():
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

            user = serializer.validated_data['user']

            # Generate JWT access and refresh tokens
            access_payload = {
                'user_id': user.id,
                'type': 'access',
                'exp': datetime.utcnow() + timedelta(minutes=15)
            }
            refresh_payload = {
                'user_id': user.id,
                'type': 'refresh',
                'exp': datetime.utcnow() + timedelta(days=7)
            }

            access_token = jwt.encode(access_payload, settings.SECRET_KEY, algorithm='HS256')
            refresh_token = jwt.encode(refresh_payload, settings.SECRET_KEY, algorithm='HS256')

            response_data = {
                'detail': 'Login successfully!',
                'user': {
                    'id': user.id,
                    'username': f"{user.first_name} {user.last_name}".strip() or user.username,
                    'email': user.email
                }
            }

            response = Response(response_data, status=status.HTTP_200_OK)

            # Cookie attributes
            secure = not getattr(settings, 'DEBUG', False)
            response.set_cookie(
                'access_token',
                access_token,
                httponly=True,
                secure=secure,
                samesite='Lax',
                max_age=15 * 60,
                path='/'
            )
            response.set_cookie(
                'refresh_token',
                refresh_token,
                httponly=True,
                secure=secure,
                samesite='Lax',
                max_age=7 * 24 * 3600,
                path='/'
            )

            return response

        except Exception as e:
            # Don't leak internal error details to clients
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    """
    API view to log out user, delete tokens and clear auth cookies.

    Requires authentication.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            # Delete DRF Token(s) associated with this user
            Token.objects.filter(user=user).delete()

            response = Response({
                'detail': 'Log-Out successfully! All Tokens will be deleted. Refresh token is now invalid.'
            }, status=status.HTTP_200_OK)

            # Remove auth cookies
            response.delete_cookie('access_token', path='/')
            response.delete_cookie('refresh_token', path='/')

            return response
        except Exception:
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RefreshTokenCookieAuthentication(BaseAuthentication):
    """Authenticate requests using the `refresh_token` cookie (JWT).

    This will raise AuthenticationFailed (401) when the cookie is missing
    or invalid. On success it returns `(user, None)`.
    """
    def authenticate(self, request):
        token = request.COOKIES.get('refresh_token')
        if not token:
            raise AuthenticationFailed('Refresh token missing')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Refresh token expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid refresh token')

        if payload.get('type') != 'refresh' or 'user_id' not in payload:
            raise AuthenticationFailed('Invalid refresh token')

        try:
            user = User.objects.get(id=payload['user_id'])
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')

        return (user, None)


class RefreshTokenView(APIView):
    """
    API view to refresh access token using refresh_token cookie.

    Requires authentication via the `refresh_token` cookie.
    On success returns a new access token and sets it as HttpOnly cookie.
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [RefreshTokenCookieAuthentication]

    def post(self, request):
        try:
            # At this point authentication has run and request.user is set
            user = request.user

            access_payload = {
                'user_id': user.id,
                'type': 'access',
                'exp': datetime.utcnow() + timedelta(minutes=15)
            }
            new_access = jwt.encode(access_payload, settings.SECRET_KEY, algorithm='HS256')

            response = Response({'detail': 'Token refreshed', 'access': new_access}, status=status.HTTP_200_OK)

            secure = not getattr(settings, 'DEBUG', False)
            response.set_cookie(
                'access_token',
                new_access,
                httponly=True,
                secure=secure,
                samesite='Lax',
                max_age=15 * 60,
                path='/'
            )

            return response

        except AuthenticationFailed as e:
            return Response({'error': str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception:
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class EmailCheckView(APIView):
    """
    API view to check if a user exists with the provided email.

    Methods:
        get(request): Returns user details if the email exists, otherwise an error.
    """
    def get(self, request):
        email = request.query_params.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'No user with this email found'}, status=status.HTTP_404_NOT_FOUND)

        return Response({
            'id': user.id,
            'email': user.email,
            'username': f"{user.first_name} {user.last_name}".strip()
        })
    