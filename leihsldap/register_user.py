import requests
import json

from leihsldap.config import config


def url(path='/'):
    base_url = config('system', 'url')
    return f'{base_url}{path}'


def check(response, error_message):
    if response.status_code >= 300:
        message = '\n'.join([
            error_message,
            f'Status code: {response.status_code}',
            response.text
            ])
        raise RuntimeError(message)


def login(session):
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


def logout(session, csrf_token):
    logout_data = {'csrf-token': csrf_token}
    session.post(url('/sign-out'), data=logout_data)


def register_user(email, firstname=None, lastname=None, username=None):
    session = requests.Session()

    csrf_token = login(session)

    # check if user is already registered
    # stop if user exists
    headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Csrf-Token': csrf_token}
    response = session.get(url(f'/admin/users/?term={email}'),
                           headers=headers)
    check(response, 'Could not request users')
    for user in response.json().get('users', []):
        if user.get('email') == email:
            return

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
                            headers=headers)
    check(response, 'Could not create user')
    user_id = response.json().get('id')

    auth = config('system', 'auth', 'id')
    path = f'/admin/system/authentication-systems/{auth}/users/{user_id}'
    response = session.put(url(path), headers=headers)
    check(response, 'Could not add user to authentication system')

    logout(session, csrf_token)


def register_auth_system():
    session = requests.Session()

    csrf_token = login(session)

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-Csrf-Token': csrf_token}

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
                            headers=headers)
    check(response, 'Could not register authenticatioon system')

    logout(session, csrf_token)

    return response.json()
