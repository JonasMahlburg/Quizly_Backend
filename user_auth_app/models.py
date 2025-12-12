from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class UserProfile(models.Model):
    """
    Extends the built-in User model with additional profile information.
    Includes optional bio and location fields.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=100, blank=True, null=True)
    

    def __str__(self):
        return self.user.username
    