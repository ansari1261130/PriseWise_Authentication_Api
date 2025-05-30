from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

class UserAuthManager(BaseUserManager):
    def create_user(self, email, username, name, terms_conditions, password=None):
        """
        Creates and saves a User with the given email, username, name, terms_conditions, and password.
        """
        if not email:
            raise ValueError("User must have an email address")
        if not username:
            raise ValueError("User must have a username")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            name=name,
            terms_conditions=terms_conditions,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, name, terms_conditions, password=None):
        """
        Creates and saves a superuser with the given email, username, name, terms_conditions, and password.
        """
        user = self.create_user(
            email=email,
            username=username,
            name=name,
            terms_conditions=terms_conditions,   # Terms and Conditions
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    email = models.EmailField(verbose_name="email address", max_length=255, unique=True)
    name = models.CharField(max_length=255)
    terms_conditions = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserAuthManager()

    USERNAME_FIELD = "email"  # Primary field for authentication
    REQUIRED_FIELDS = ["username", "name", "tc"]  # Additional required fields

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin
