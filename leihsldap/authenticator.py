import jwt
import time

from leihsldap.config import config


def response_url(sign_in_token_data, success_token):
    base_url = sign_in_token_data['server_base_url']
    path = sign_in_token_data['path']
    return f'{base_url}{path}?token={success_token}'


def token_data(token):
    options = {'verify_exp': not config('token', 'allow_expired')}
    private_key = config('token', 'private_key')
    return jwt.decode(token, private_key, ['ES256'], options)


def authenticate(token):
    data = token_data(token)

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

    return data, response_url(data, success_token)
