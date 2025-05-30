from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailOrUsernameAuthBackend(ModelBackend):
    """
    Custom authentication backend that allows users to log in with either
    their username or email.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=username)  # Try email first
        except User.DoesNotExist:
            try:
                user = User.objects.get(username=username)  # Try username
            except User.DoesNotExist:
                return None

        if user and user.check_password(password):
            return user
        return None
