import requests

from leihsldap.config import config


def api(method: str, path: str, **kwargs) -> requests.models.Response:
    '''Execute an HTTP request against the Leihs API.
    This uses the API token from the configuration file.

    :param method: HTTP method to use
    :param path: Path of the request URL
    :returns: HTTP response
    '''
    base_url = config('system', 'url')
    url = f'{base_url}{path}'
    headers = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Authorization': 'Token ' + config('system', 'api_token')}
    return requests.request(method, url, headers=headers, **kwargs)


def check(response, error_message: str) -> None:
    '''Check if the response contains an HTTP error code and raise an exception
    if it does. The exception message will contain additional information
    returned by the request.

    :param response: HTTP response return by requests library
    :param error_message: Error message to include if an exception is raised
    :raises: RuntimeError
    '''
    if response.status_code >= 300:
        message = '\n'.join([
            error_message,
            f'Status code: {response.status_code}',
            response.text
            ])
        raise RuntimeError(message)


def register_user(email: str,
                  firstname: str = None,
                  lastname: str = None,
                  username: str = None):
    '''Register a new user with Leihs.
    Skip registration if the user already exists.

    :param email: Email address
    :param firstname: The user's given name
    :param lastname: The user's family name
    :param username: The user's login
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
    response = api('post', '/admin/users/', json=user_data)

    # It's fine if we get a conflict.
    # That just means, the user is already registered
    if response.status_code != 409:
        check(response, 'Could not create user')

        # add the newly created user to the authentication system
        auth = config('system', 'auth', 'id')
        user_id = response.json().get('id')
        path = f'/admin/system/authentication-systems/{auth}/users/{user_id}'
        response = api('put', path)
        check(response, 'Could not add user to authentication system')


def register_auth_system() -> dict:
    '''Register the authentication system with Leihs.
    Registration data are taken from the configuration.

    :returns: Dictionary with authentication system data
    '''
    # register system
    system_data = {
        'description': config('system', 'auth', 'description'),
        'enabled': True,
        'external_public_key': config('token', 'public_key'),
        'external_sign_in_url': config('system', 'auth', 'url'),
        'id': config('system', 'auth', 'id', allow_empty=False),
        'internal_private_key': config('token', 'private_key'),
        'internal_public_key': config('token', 'public_key'),
        'name': config('system', 'auth', 'name'),
        'priority': config('system', 'auth', 'priority') or 3,
        'send_email': True,
        'send_login': True,
        'type': 'external',
        'sign_up_email_match': config('system', 'auth', 'email_match')
        }
    response = api('post',
                   '/admin/system/authentication-systems/',
                   json=system_data)
    check(response, 'Could not register authentication system')
    return response.json()
