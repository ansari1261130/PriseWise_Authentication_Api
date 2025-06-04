from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

class UserAuthManager(BaseUserManager):
    def create_user(self, email, username, name, terms_conditions, password=None):
        if not email:
            raise ValueError("User must have an email address")
        if not username:
            raise ValueError("User must have a username")
        if not terms_conditions:
            raise ValueError("User must accept terms and conditions")

        email = self.normalize_email(email)
        user = self.model(
            email=email,
            username=username,
            name=name,
            terms_conditions=terms_conditions,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, name, terms_conditions=True, password=None):
        user = self.create_user(
            email=email,
            username=username,
            name=name,
            terms_conditions=terms_conditions,
            password=password,
        )
        user.is_admin = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    username = models.CharField(max_length=150, unique=True)  # removed null=True, blank=True
    email = models.EmailField(verbose_name="email address", max_length=255, unique=True)
    name = models.CharField(max_length=255)
    terms_conditions = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)  # Add this field for admin permissions
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserAuthManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username", "name", "terms_conditions"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin
