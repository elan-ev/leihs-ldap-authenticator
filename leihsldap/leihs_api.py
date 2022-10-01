import requests
import json

from leihsldap.config import config


def url(path: str = '/') -> str:
    '''Turn a relative path into a URL for the targeted Leihs system.

    :param path: Path of the URL
    :returns: URL to Leihs
    '''
    base_url = config('system', 'url')
    return f'{base_url}{path}'


def headers(csrf_token: str) -> dict:
    '''Return default set of HTTP headers for Leihs API.

    :param csrf_token: CSRF token for Leihs
    :returns: Dictionary of HTTP headers
    '''
    return {'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Csrf-Token': csrf_token}


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


def login(session) -> str:
    '''Start an authenticated syssion by logging in to Leihs.

    :param session: Session created by requests library
    :returns: CSRF token for Leihs
    '''
    # get csrf_token
    response = session.get(url())
    check(response, 'Could not get landing page')
    csrf_token = response.cookies.get('leihs-anti-csrf-token')

    # log in as admin
    login_data = {
            'csrf-token': csrf_token,
            'user': config('system', 'admin', 'user'),
            'password': config('system', 'admin', 'password')
            }
    response = session.post(url('/sign-in'), data=login_data)
    check(response, 'Could not sign in')

    return csrf_token


def logout(session, csrf_token) -> None:
    '''Log out from Leihs, ending the authenticated session.

    :param session: Session created by requests library
    :param csrf_token: CSRF token for Leihs
    '''
    logout_data = {'csrf-token': csrf_token}
    session.post(url('/sign-out'), data=logout_data)


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
    session = requests.Session()

    csrf_token = login(session)

    # register new user
    user_data = json.dumps({
            'email': email,
            'firstname': firstname,
            'lastname': lastname,
            'account_enabled': True,
            'password_sign_in_enabled': False,
            'login': username,
            'extended_info': None
            })
    response = session.post(url('/admin/users/'),
                            data=user_data,
                            headers=headers(csrf_token))

    # It's fine if we get a conflict.
    # That just means, the user is already registered
    if response.status_code != 409:
        check(response, 'Could not create user')
        user_id = response.json().get('id')

        # add the newly created user to the authentication system
        auth = config('system', 'auth', 'id')
        path = f'/admin/system/authentication-systems/{auth}/users/{user_id}'
        response = session.put(url(path), headers=headers(csrf_token))
        check(response, 'Could not add user to authentication system')

    logout(session, csrf_token)


def register_auth_system() -> dict:
    '''Register the authentication system with Leihs.
    Registration data are taken from the configuration.

    :returns: Dictionary with authentication system data
    '''
    session = requests.Session()
    csrf_token = login(session)

    # register system
    system_data = json.dumps({
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
        })
    response = session.post(url('/admin/system/authentication-systems/'),
                            data=system_data,
                            headers=headers(csrf_token))
    check(response, 'Could not register authentication system')

    logout(session, csrf_token)

    return response.json()
