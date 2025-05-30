from django.contrib import admin
from .models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group

class UserAdminModel(BaseUserAdmin):
    list_display = ["id", "email", "username", "name", "terms_conditions", "is_admin"]
    list_filter = ["is_admin"]

    fieldsets = [
        (None, {"fields": ["email", "password"]}),
        ("Personal info", {"fields": ["username", "name", "terms_conditions"]}),  
        ("Permissions", {"fields": ["is_admin"]}),
    ]

    add_fieldsets = [
        (
            None,
            {
                "classes": ["wide"],
                "fields": ["email", "username", "name", "terms_conditions", "password1", "password2"],  
            },
        ),
    ]
    
    search_fields = ["email", "username"]
    ordering = ["email"]
    filter_horizontal = []

admin.site.register(User, UserAdminModel)
admin.site.unregister(Group)
