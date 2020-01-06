from typing import Optional, Type

from django.contrib.auth.base_user import AbstractBaseUser
from rest_framework.authentication import (
    BaseAuthentication,
    TokenAuthentication
)


class TokenDoesNotExist(ValueError):

    def __init__(self):
        super().__init__("Token does not exist")


class AbstractAuthTokenManager:

    def get_authentication_class(self) -> Type[BaseAuthentication]:
        """
        Return authentication class which is able to parse the token.
        This is used to ensure that the class is added
        in ``REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']`` setting.
        """
        raise NotImplementedError()

    def get_app_name(self) -> str:
        """
        Return the Django app name which needs to be installed so
        this token manager class works properly.
        """
        raise NotImplementedError()

    def provide_token(self, user: AbstractBaseUser) -> str:
        """
        Get or create token for given user.
        If there is no token to provide, raise ``ValueError``.
        """
        raise NotImplementedError()

    def revoke_token(
            self, user: AbstractBaseUser, *,
            token: Optional[str] = None) -> None:
        """
        Revoke the given token for a given user. If the token is not provided,
        revoke all tokens for given user.
        If the provided token is invalid or there is no token to revoke,
        raise ``ValueError``.
        This method may not be implemented in all cases - for instance, in case
        when the token is cryptographically generated and not stored
        in the database.
        """
        raise NotImplementedError()


class RestFrameworkAuthTokenManager(AbstractAuthTokenManager):

    def get_authentication_class(self) -> Type[BaseAuthentication]:
        return TokenAuthentication

    def get_app_name(self) -> str:
        return 'rest_framework.authtoken'

    def provide_token(self, user: AbstractBaseUser) -> str:
        from rest_framework.authtoken.models import Token  # noqa: E501 pylint: disable=import-outside-toplevel

        token_obj, _ = Token.objects.get_or_create(user=user)
        return token_obj.key

    def revoke_token(
            self, user: AbstractBaseUser, *,
            token: Optional[str] = None) -> None:
        from rest_framework.authtoken.models import Token  # noqa: E501 pylint: disable=import-outside-toplevel

        try:
            token_obj = Token.objects.get(user_id=user.pk)  # type: Token
        except Token.DoesNotExist:
            raise TokenDoesNotExist()

        if token is not None and token_obj.key != token:
            raise TokenDoesNotExist()

        token_obj.delete()
