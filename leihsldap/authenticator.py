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
import time

from leihsldap.config import config


def token_data(token):
    options = {'verify_exp': not config('token', 'allow_expired')}
    private_key = config('token', 'private_key')
    return jwt.decode(token, private_key, ['ES256'], options)


def response_url(token, data):
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

    base_url = data['server_base_url']
    path = data['path']
    return f'{base_url}{path}?token={success_token}'
