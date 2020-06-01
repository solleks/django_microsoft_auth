import json
import logging
import secrets

import jwt
import msal
import requests
from django.contrib.sites.models import Site
from django.core.cache import cache
from django.core.signing import TimestampSigner
from django.middleware.csrf import CSRF_TOKEN_LENGTH
from django.urls import reverse
from jwt.algorithms import RSAAlgorithm
from requests_oauthlib import OAuth2Session

from .conf import (
    CACHE_KEY_JWKS,
    CACHE_KEY_OPENID,
    CACHE_TIMEOUT,
)
from .models import AzureADConfiguration
from .utils import get_scheme

logger = logging.getLogger("django")


class MicrosoftClient(OAuth2Session):
    """ Simple Microsoft OAuth2 Client to authenticate them

        Extended from Requests-OAuthlib's OAuth2Session class which
            does most of the heavy lifting

        https://requests-oauthlib.readthedocs.io/en/latest/

        Microsoft OAuth documentation can be found at
        https://developer.microsoft.com/en-us/graph/docs/get-started/rest
    """

    _config_url = "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"  # noqa
    _authority_url = "https://login.microsoftonline.com/{tenant}"

    config = None
    azure_ad_config = None

    # required OAuth scopes
    SCOPE_MICROSOFT = ["openid", "email", "profile"]

    # MSAL
    # MSAL automatically includes the scopes "openid", "profile" and
    # "offline_access" and complains if you include them.
    SCOPE_MICROSOFT_MSAL = ["email"]
    # /MSAL

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

        try:
            current_site = Site.objects.get_current(request)
        except Site.DoesNotExist:
            current_site = Site.objects.first()

        domain = current_site.domain
        path = reverse("microsoft_auth:auth-callback")
        scope = " ".join(self.SCOPE_MICROSOFT).strip()

        scheme = get_scheme(request, self.config)

        # MSAL
        authority_url = self._authority_url.format(
            tenant=self.azure_ad_config.tenant_id)
        # A token_cache can be specified in the constructor.
        # https://msal-python.readthedocs.io/en/latest/#tokencache
        self.redirect_uri="{0}://{1}{2}".format(scheme, domain, path),
        self.confidential_client = msal.ConfidentialClientApplication(
            self.azure_ad_config.client_id,
            client_credential=self.azure_ad_config.client_secret,
            authority=authority_url)
        # /MSAL

        self.use_msal = True

        super().__init__(
            self.azure_ad_config.client_id,
            scope=scope,
            state=state,
            redirect_uri="{0}://{1}{2}".format(scheme, domain, path),
            *args,
            **kwargs
        )

    @property
    def _openid_config(self):
        config = cache.get(CACHE_KEY_OPENID)

        if config is None:
            config_url = self._config_url.format(
                tenant=self.config.MICROSOFT_AUTH_TENANT_ID
            )
            response = self.get(config_url)

            if response.ok:
                config = response.json()
                cache.set(CACHE_KEY_OPENID, config, CACHE_TIMEOUT)

        return config

    @property
    def _jwks(self):
        jwks = cache.get(CACHE_KEY_JWKS, [])

        if len(jwks) == 0:
            jwks_uri = self._openid_config["jwks_uri"]
            if jwks_uri is None:
                return []

            response = self.get(jwks_uri)

            if response.ok:
                jwks = response.json()["keys"]
                cache.set(CACHE_KEY_JWKS, jwks, CACHE_TIMEOUT)
        return jwks

    def get_claims(self, allow_refresh=True):
        if self.token is None:
            return None

        token = self.token["id_token"].encode("utf8")

        kid = jwt.get_unverified_header(token)["kid"]
        public_key = None
        for key in self._jwks:
            if kid == key["kid"]:
                jwk = key
                break

        if jwk is None:
            if allow_refresh:
                logger.warn(
                    "could not find public key for id_token, "
                    "refreshing OIDC config"
                )
                cache.delete(CACHE_KEY_JWKS)
                cache.delete(CACHE_KEY_OPENID)

                return self.get_claims(allow_refesh=False)
            else:
                logger.warn("could not find public key for id_token")
                return None

        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))

        try:
            claims = jwt.decode(
                token,
                public_key,
                algoithm="RS256",
                audience=self.azure_ad_config.client_id,
            )
        except jwt.PyJWTError as e:
            logger.warn("could verify id_token sig: {}".format(e))
            return None

        print('get_claims:', claims)
        return claims

    def authorization_url(self):
        """ Generates Office 365 Authorization URL """

        auth_url = self._openid_config["authorization_endpoint"]
        print('auth_url:', auth_url)

        if self.use_msal:
            # MSAL
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
            print(u, state)
            msal_auth_url = self.confidential_client.get_authorization_request_url(
                self.SCOPE_MICROSOFT_MSAL,
                state=state,
                redirect_uri=self.redirect_uri
            )
            print('msal_auth_url:', msal_auth_url)
            # TODO(Charlie): Should we pass back signed state as well as URL?
            return msal_auth_url
            # /MSAL
        else:
            super_auth_url = super().authorization_url(auth_url, response_mode="form_post")
            print('super_auth_url:', super_auth_url)
            return super_auth_url[0]

    def fetch_token(self, **kwargs):
        """ Fetches OAuth2 Token with given kwargs"""

        fetched_token = None
        # An authorization code can only be used once, so we can't call
        # both APIs and compare.
        if self.use_msal:
            # MSAL
            # code to come from request that went to auth-callback
            print('Acquire token by authorization')
            fetched_token = self.confidential_client.acquire_token_by_authorization_code(
                kwargs.get('code'), scopes=self.SCOPE_MICROSOFT_MSAL)
            self.token = fetched_token
            # Hack to make the token's scope be a list.
            # TODO(Charlie): Remove this when we only use MSAL.
            fetched_token['scope'] = fetched_token['scope'].split()
            # /MSAL
        else:
            fetched_token = super().fetch_token(  # pragma: no cover
                self._openid_config["token_endpoint"],
                client_secret=self.azure_ad_config.client_secret,
                **kwargs
            )
        print('fetched_token:', fetched_token)
        print('fetched token scopes:', fetched_token['scope'])
        return fetched_token

    def valid_scopes(self, scopes):
        """ Validates response scopes """
        scopes = set(scopes)
        required_scopes = set(self.SCOPE_MICROSOFT)

        print('scopes({})'.format(scopes))
        print('required_scopes({})'.format(required_scopes))
        print(required_scopes <= scopes)

        # verify all require_scopes are in scopes
        return required_scopes <= scopes
