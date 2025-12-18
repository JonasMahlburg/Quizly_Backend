from django.urls import path
from .views import UserProfileList, UserProfileDetail, RegistrationView, CustomLogInView, LogoutView, RefreshTokenView

urlpatterns = [
    path('profiles/', UserProfileList.as_view(), name='userprofile-list'),
    path('profiles/<int:pk>/', UserProfileDetail.as_view(), name= 'userprofile-detail'),
    path('register/', RegistrationView.as_view(), name='registration'),
    path('login/', CustomLogInView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token-refresh'),
]