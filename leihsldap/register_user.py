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


def register_user(email, firstname=None, lastname=None, login=None):
    session = requests.Session()

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

    # check if user is already registered
    # stop if user exists
    headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Csrf-Token': csrf_token}
    response = session.get(url(f'/admin/users/?term={email}'),
                           headers=headers)
    check(response, 'Could not request users')
    print(response.json())
    print(response.json().get('users', []))
    for user in response.json().get('users', []):
        if user.get('email') == email:
            return

    user_data = json.dumps({
            'email': email,
            'firstname': firstname,
            'lastname': lastname,
            'account_enabled': True,
            'password_sign_in_enabled': False,
            'login': login,
            'extended_info': None
            })
    response = session.post(url('/admin/users/'),
                            data=user_data,
                            headers=headers)
    check(response, 'Could not create user')
    user_id = response.json().get('id')

    auth = config('system', 'auth_id')
    path = f'/admin/system/authentication-systems/{auth}/users/{user_id}'
    response = session.put(url(path), headers=headers)
    check(response, 'Could not add user to authentication system')

    # log out again
    logout_data = {'csrf-token': csrf_token}
    session.post(url('/sign-out'), data=logout_data)
