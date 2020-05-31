from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db import models
from django.utils.translation import ugettext_lazy as _


class UnicodeSpaceUsernameValidator(UnicodeUsernameValidator):
    """ validator to allow spaces in username """

    regex = r"^[\w\.@+\- ]+$"


# replace UnicodeUsernameValidator on User model...
User = get_user_model()
for field in User._meta.fields:
    if field.name == "username":
        for index, validator in enumerate(field.validators):
            if isinstance(validator, UnicodeUsernameValidator):
                field.validators[index] = UnicodeSpaceUsernameValidator()


class MicrosoftAccount(models.Model):
    microsoft_id = models.CharField(_("microsoft account id"), max_length=64)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        related_name="microsoft_account",
    )

    def __str__(self):
        return self.microsoft_id


# TODO(Charlie): Max lengths are just estimated, not taken from any docs.
# TODO(Charlie): Link SSO configurations to projects: 1 SSO -> many projects,
#                1 project -> 0 or 1 SSO.
class AzureADConfiguration(models.Model):
    project = models.CharField(max_length=64)
    tenant_id = models.CharField(max_length=64)
    client_id = models.CharField(max_length=64)
    client_secret = models.CharField(max_length=64)

    def __str__(self):
        return "Project: {}\nTenant ID: {}\nClient ID: {}\nClient secret: {}".format(self.project, self.tenant_id, self.client_id, self.client_secret)
