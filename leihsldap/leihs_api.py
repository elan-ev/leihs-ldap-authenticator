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

import logging
import requests

from typing import Optional

from leihsldap.config import config

# Logger
logger = logging.getLogger(__name__)


def api(method: str, path: str, **kwargs) -> requests.models.Response:
    '''Execute an HTTP request against the Leihs API.
    This uses the API token from the configuration file.

    :param method: HTTP method to use
    :param path: Path of the request URL
    :returns: HTTP response
    '''
    base_url = config('leihs', 'url', allow_empty=False)
    url = f'{base_url}{path}'
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Authorization': 'Token ' + config('leihs', 'api_token')}
    logger.debug('Sending request to %s', url)
    return requests.request(method, url, headers=headers, **kwargs)


def check(response: requests.models.Response, error_message: str) -> None:
    '''Check if the response contains an HTTP error code and raise an exception
    if it does. The exception message will contain additional information
    returned by the request.

    :param response: HTTP response return by requests library
    :param error_message: Error message to include if an exception is raised
    :raises RuntimeError: HTTP error response detected
    '''
    if response.status_code >= 300:
        message = '\n'.join([
            error_message,
            f'Status code: {response.status_code}',
            response.text
            ])
        raise RuntimeError(message)


def register_user(email: str,
                  firstname: Optional[str] = None,
                  lastname: Optional[str] = None,
                  username: Optional[str] = None,
                  groups: list[str] = []):
    '''Register a new user with Leihs.
    Skip registration if the user already exists.

    :param email: Email address
    :param firstname: The user's given name
    :param lastname: The user's family name
    :param username: The user's login
    :param groups: List of groups to add user to when initially created
    '''
    # register new user
    user_data = {
        'email': email,
        'firstname': firstname,
        'lastname': lastname,
        'account_enabled': True,
        'password_sign_in_enabled': False,
        'login': username,
        'extended_info': None
        }
    logger.debug('Trying to register user: %s', user_data)
    response = api('post', '/admin/users/', json=user_data)

    # It's fine if we get a conflict.
    # That just means, the user is already registered
    if response.status_code != 409:
        logger.debug('New user created. Adding authentication and groups.')
        check(response, 'Could not create user')

        # add the newly created user to the authentication system
        user_data = response.json()
        add_user_to_auth(user_data['id'])

        # add user to groups
        for group in groups:
            group_data = create_group(group)
            add_user_to_group(user_data['id'], group_data['id'])


def add_user_to_auth(user_id: str) -> None:
    '''Add user to the authentication system.

    :param user_id: Identifier of the user to add.
    '''
    auth_id = config('auth-system', 'id')
    path = f'/admin/system/authentication-systems/{auth_id}/users/{user_id}'
    logger.debug('Adding user `%s` to authentication system `%s`',
                 user_id, auth_id)
    response = api('put', path)
    check(response, 'Could not add user to authentication system')


def register_auth_system() -> None:
    '''Register the authentication system with Leihs.
    Registration data are taken from the configuration.

    :returns: Dictionary with authentication system data
    '''
    # register system
    system_data = {
        'description': config('auth-system', 'description'),
        'enabled': True,
        'external_public_key': config('token', 'public_key'),
        'external_sign_in_url': config('auth-system', 'url'),
        'id': config('auth-system', 'id', allow_empty=False),
        'internal_private_key': config('token', 'private_key'),
        'internal_public_key': config('token', 'public_key'),
        'name': config('auth-system', 'name'),
        'priority': config('auth-system', 'priority') or 3,
        'send_email': True,
        'send_login': True,
        'type': 'external',
        'sign_up_email_match': config('auth-system', 'email_match')
        }
    logger.debug('Trying to register authentication system `%s´',
                 system_data['id'])
    response = api('post',
                   '/admin/system/authentication-systems/',
                   json=system_data)

    # If we got a 409, the system is already registered and everything is good
    if response.status_code == 409:
        logger.debug('Authentication system was already registered.')
        return

    # If we got anything else, check for errors
    check(response, 'Could not register authentication system')


def create_group(name: str) -> dict:
    '''Create group if it does not yet exists.

    :param name: Name of the group to create. Also used as org_id.
    :returns: Dictionary of user data
    '''
    group_data = {
        'name': name,
        'org_id': name,
        'organization': 'leihs-local'
        }
    logger.debug('Trying to create group %s', name)
    response = api('post', '/admin/groups/', json=group_data)

    # If we just created the group, we have all data we need
    if response.status_code != 409:
        check(response, 'Could not create group')
        return response.json()

    # if the group already existed, get the existing group's data
    logger.debug('Group already existed. Getting info from existing group')
    del group_data['name']
    response = api('get', '/admin/groups/', params=group_data)
    check(response, 'Could not get group data')
    groups_found = response.json().get('groups', [])
    if len(groups_found) != 1:
        raise RuntimeError(f'Got invalid group data: {groups_found}')
    return groups_found[0]


def add_user_to_group(user_id: str, group_id: str):
    '''Add a user to a group in Leihs.

    :param user_id: Identifier of the user to add
    :param group_id: Identifier of the Group to add the user to
    '''
    logger.debug('Trying to add user `%s` to group `%s`.', user_id, group_id)
    response = api('put', f'/admin/groups/{group_id}/users/{user_id}')
    check(response, 'Could not add user to group')
    return response
