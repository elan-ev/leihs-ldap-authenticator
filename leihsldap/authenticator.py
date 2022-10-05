# LDAP based authentication handler for Leihs
# Copyright 2022 ELAN e.V.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import jwt
import logging
import time

from leihsldap.config import config

# Logger
logger = logging.getLogger(__name__)


def token_data(token: str) -> tuple[dict[str, list], str, str, bool]:
    '''Verify JWT token and extract data contained within token.

    :param token: The JWT token.
    :returns: Tuple of original data, email, login and if the user is already
        registered
    '''
    options = {'verify_exp': not config('token', 'allow_expired')}
    private_key = config('token', 'private_key')
    data = jwt.decode(token, private_key, ['ES256'], options)

    email = data.get('email')
    login = data.get('login')
    if type(email) is not str:
        raise RuntimeError('Field email must be set.')
    # If a user does not exist, Leihs will treat the entered value as an email.
    # If the value identifies a user, Leihs will supply the login it knows.
    # We always set login, so we can use this to check if a user is registered.
    if type(login) is str:
        logger.debug('Login attempt from already registered user `%s` (`%s`)',
                     login, email)
        return data, email, login, True
    login = email.split('@', 1)[0]
    logger.debug('Login attempt from unregistered user `%s` (`%s`)',
                 login, email)
    return data, email, login, False


def response_url(token: str, data: dict[str, str]) -> str:
    '''Generate response URL to redirect to after authentication.
    The URL should point to Leihs and will contain a success token with user
    information to identify the user in Leihs.

    :param token: Original request token from Leihs.
    :param data: User data to pass on to Leihs.
    '''
    # generate success token
    iat = int(time.time())
    exp = iat + config('token', 'validity')
    private_key = config('token', 'private_key')
    success_token = jwt.encode({
            'sign_in_request_token': token,
            'email': data.get('email'),
            'iat': iat,
            'exp': exp,
            'success': True
            }, private_key, 'ES256')

    logger.debug('returning success token: %s', success_token)
    base_url = data['server_base_url']
    path = data['path']
    return f'{base_url}{path}?token={success_token}'
