from django.urls import path
from .views import UserProfileList, UserProfileDetail, RegistrationView, CustomLogInView

urlpatterns = [
    path('profiles/', UserProfileList.as_view(), name='userprofile-list'),
    path('profiles/<int:pk>/', UserProfileDetail.as_view(), name= 'userprofile-detail'),
    path('registration/', RegistrationView.as_view(), name='registration'),
    path('login/', CustomLogInView.as_view(), name='login')
]