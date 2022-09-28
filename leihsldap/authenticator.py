import jwt
import time

from leihsldap.config import config


def response_url(sign_in_token_data, success_token):
    base_url = sign_in_token_data['server_base_url']
    path = sign_in_token_data['path']
    return f'{base_url}{path}?token={success_token}'


def token_data(token):
    options = {}

    # Fall back to demo token for development if one is provided
    if not token:
        print('Warning: Using demo token')
        token = config('token', 'demo')

    if config('token', 'allow_expired'):
        options = {'verify_exp': False}
    private_key = config('token', 'private_key')
    return jwt.decode(token, private_key, ['ES256'], options)


def authenticate(token):
    options = {}
    if config('token', 'allow_expired'):
        options = {'verify_exp': False}
    private_key = config('token', 'private_key')
    data = jwt.decode(token, private_key, ['ES256'], options)
    email = data['email']

    # generate success token
    iat = int(time.time())
    exp = iat + config('token', 'validity')
    success_token = jwt.encode({
            'sign_in_request_token': token,
            'email': email,
            'iat': iat,
            'exp': exp,
            'success': True
            }, private_key, 'ES256')

    return data, response_url(data, success_token)
