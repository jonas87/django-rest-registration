from rest_framework.authentication import BaseAuthentication

from rest_registration.auth_token_managers import AbstractAuthTokenManager


class FaultyAuthTokenManager(AbstractAuthTokenManager):

    def get_authentication_class(self):
        return BaseAuthentication

    def get_app_name(self):
        return 'nonexistent.app'

    def provide_token(self, user):
        raise ValueError("could not provide token")

    def revoke_token(self, user, *, token=None):
        raise ValueError("could not revoke token")
