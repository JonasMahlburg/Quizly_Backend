from rest_framework import generics, status
from django.contrib.auth.models import User
from user_auth_app.models import UserProfile
from .serializers import RegistrationSerializer, EmailAuthTokenSerializer
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response


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
    API view for user login using token authentication.

    Authenticates user based on provided email and password.
    Returns token and user information on success.

    Methods:
        post(): Authenticates and logs in the user.
    """
    permission_classes= [AllowAny]
    serializer_class= EmailAuthTokenSerializer  

    def post(self, request):
        serializer = self.serializer_class(
            data={
                'email': request.data.get('email'),
                'password': request.data.get('password')
            },
            context={'request': request}
        )

        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, _ = Token.objects.get_or_create(user=user)
            username = f"{user.first_name} {user.last_name}".strip()
            data = {
                'token': token.key,
                'username': username,
                'email': user.email,
                'user_id': user.id
            }
            return Response(data)
        else:
            return Response(
                {'error': 'Invalid email or password'},
                status=status.HTTP_400_BAD_REQUEST)
            

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
    