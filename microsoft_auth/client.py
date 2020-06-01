import json
import logging
import secrets

import msal
from django.contrib.sites.models import Site
from django.core.cache import cache
from django.core.signing import TimestampSigner
from django.middleware.csrf import CSRF_TOKEN_LENGTH
from django.urls import reverse

from .models import AzureADConfiguration
from .utils import get_scheme

logger = logging.getLogger("django")


class MicrosoftClient:
    """ Simple Microsoft OAuth2 Client to authenticate them

        Microsoft OAuth documentation can be found at
        https://developer.microsoft.com/en-us/graph/docs/get-started/rest
    """
    _authority_url = "https://login.microsoftonline.com/{tenant}"

    config = None
    azure_ad_config = None

    # required OAuth scopes
    SCOPE_MICROSOFT = ["openid", "email", "profile"]

    # MSAL automatically includes the scopes "openid", "profile" and
    # "offline_access" and complains if you include them.
    SCOPE_MICROSOFT_MSAL = ["email"]

    def __init__(self, state=None, request=None, *args, **kwargs):
        from .conf import config

        self.config = config
        self.azure_ad_config = None
        try:
            self.azure_ad_config = AzureADConfiguration.objects.get(
                project='some_project')
        except AzureADConfiguration.DoesNotExist:
            self.azure_ad_config = AzureADConfiguration(
                project='dummy',
                tenant_id=self.config.MICROSOFT_AUTH_TENANT_ID,
                client_id=self.config.MICROSOFT_AUTH_CLIENT_ID,
                client_secret=self.config.MICROSOFT_AUTH_CLIENT_SECRET
            )
        self.token = None

        try:
            current_site = Site.objects.get_current(request)
        except Site.DoesNotExist:
            current_site = Site.objects.first()

        domain = current_site.domain
        path = reverse("microsoft_auth:auth-callback")
        scope = " ".join(self.SCOPE_MICROSOFT).strip()

        scheme = get_scheme(request, self.config)

        authority_url = self._authority_url.format(
            tenant=self.azure_ad_config.tenant_id)
        # A token_cache can be specified in the constructor.
        # https://msal-python.readthedocs.io/en/latest/#tokencache
        self.redirect_uri="{0}://{1}{2}".format(scheme, domain, path)
        self.confidential_client = msal.ConfidentialClientApplication(
            self.azure_ad_config.client_id,
            client_credential=self.azure_ad_config.client_secret,
            authority=authority_url)

    def get_claims(self, allow_refresh=True):
        if self.token is not None and "id_token_claims" in self.token:
            return self.token["id_token_claims"]

        return None

    def authorization_url(self):
        """ Generates Office 365 Authorization URL """
        # Consider using other parameters.
        # Method documentation:
        # https://msal-python.readthedocs.io/en/latest/#msal.ClientApplication.get_authorization_request_url
        # TODO(Charlie): Should we use a CSRF token as the state value?
        UNICODE_ASCII_CHARACTER_SET = ('abcdefghijklmnopqrstuvwxyz'
                                       'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                       '0123456789')
        rand = secrets.SystemRandom()
        u = ''.join(rand.choice(UNICODE_ASCII_CHARACTER_SET) for x in range(CSRF_TOKEN_LENGTH))
        signer = TimestampSigner()
        state = signer.sign(u)
        msal_auth_url = self.confidential_client.get_authorization_request_url(
            self.SCOPE_MICROSOFT_MSAL,
            state=state,
            redirect_uri=self.redirect_uri
        )
        # TODO(Charlie): Should we pass back signed state as well as URL?
        return msal_auth_url

    def fetch_token(self, **kwargs):
        """ Fetches OAuth2 Token with given kwargs"""

        fetched_token = None
        # An authorization code can only be used once, so we can't call
        # both APIs and compare.
        # code to come from request that went to auth-callback
        fetched_token = self.confidential_client.acquire_token_by_authorization_code(
            kwargs.get('code'), scopes=self.SCOPE_MICROSOFT_MSAL)
        self.token = fetched_token
        return fetched_token

    def valid_scopes(self, scopes):
        """ Validates response scopes """
        # scopes argument is a space-separated string of scope names
        scopes = set(scopes.split())
        required_scopes = set(self.SCOPE_MICROSOFT)

        # verify all require_scopes are in scopes
        return required_scopes <= scopes
