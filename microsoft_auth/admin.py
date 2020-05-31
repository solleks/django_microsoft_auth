from django.apps import apps
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .conf import config
from .models import MicrosoftAccount, AzureADConfiguration

__all__ = [
    "MicrosoftAccountAdmin",
    "MicrosoftAccountInlineAdmin",
    "UserAdmin",
]

User = get_user_model()

# override admin site template
admin.site.login_template = "microsoft/admin_login.html"

# djangoql support
extra_base = []
if apps.is_installed("djangoql"):  # pragma: no branch
    from djangoql.admin import DjangoQLSearchMixin

    extra_base = [DjangoQLSearchMixin]

base_admin = extra_base + [admin.ModelAdmin]
base_user_admin = extra_base + [BaseUserAdmin]

# unregister User mode if it is already registered
if admin.site.is_registered(User):  # pragma: no branch
    admin.site.unregister(User)


class MicrosoftAccountAdmin(*base_admin):
    readonly_fields = ("microsoft_id",)


class MicrosoftAccountInlineAdmin(admin.StackedInline):
    model = MicrosoftAccount
    readonly_fields = ("microsoft_id",)


def _register_admins():
    if admin.site.is_registered(MicrosoftAccount):
        admin.site.unregister(MicrosoftAccount)

    admin.site.register(MicrosoftAccount, MicrosoftAccountAdmin)
    admin.site.register(AzureADConfiguration)


def _get_inlines():
    return [MicrosoftAccountInlineAdmin]


@admin.register(User)
class UserAdmin(*base_user_admin):
    @property
    def inlines(self):
        """ Adds MicrosoftAccount foreign key to User model """

        return _get_inlines()


_register_admins()
