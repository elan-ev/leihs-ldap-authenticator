import os
import yaml

from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError
from flask import Flask, request, redirect, render_template
from functools import wraps
from jwt.exceptions import DecodeError, ExpiredSignatureError

from leihsldap.authenticator import authenticate, token_data
from leihsldap.register_user import register_user, register_auth_system
from leihsldap.config import config

flask_config = {}
if config('ui', 'directories', 'template'):
    flask_config['template_folder'] = config('ui', 'directories', 'template')
if config('ui', 'directories', 'static'):
    flask_config['static_folder'] = config('ui', 'directories', 'static')
app = Flask(__name__, **flask_config)

__error = {}


def ensure_list(var):
    if type(var) is list:
        return var
    return [var]


def verify_password(username, password):
    user_dn = config('ldap', 'user_dn').format(username=username)

    server = Server(
            config('ldap', 'server'),
            port=config('ldap', 'port'),
            use_ssl=True,
            get_info=ALL)
    conn = Connection(server, user_dn, password, auto_bind=True)

    conn.search(
            config('ldap', 'base_dn'),
            config('ldap', 'search_filter').format(username=username),
            attributes=['sn', 'givenName', 'mail'])
    if len(conn.entries) != 1:
        raise ValueError('Search must return exactly one result', conn.entries)
    return conn.entries[0]


def login_data(data):
    email = data.get('email')
    login = data.get('login')
    if login:
        return email, login, True
    login = email.split('@', 1)[0]
    return email, login, False


def error(id, code):
    if not __error:
        with open(os.path.dirname(__file__) + '/error.yml', 'r') as f:
            globals()['__error'] = yaml.safe_load(f)
    error_data = __error.get(id).copy()
    error_data['leihs_url'] = config('system', 'url')
    return render_template('error.html', **error_data), code


def handle_errors(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except DecodeError:
            return error('invalid_token', 400)
        except ExpiredSignatureError:
            return error('expired_token', 400)
        except LDAPBindError:
            return error('invalid_credentials', 403)
    return wrapper


@app.before_first_request
def before_first_request():
    try:
        register_auth_system()
    except RuntimeError:
        print('Could not register authentication system. System is likely '
              'already registered')


@app.errorhandler(500)
def internal_server_error(e):
    return error('internal', 500)


@app.route('/', methods=['GET'])
@handle_errors
def login_page():
    token = request.args.get('token')
    if not token:
        return error('no_token', 400)
    data = token_data(token)
    email, user, _ = login_data(data)
    return render_template('login.html', token=token, user=user)


@app.route('/', methods=['POST'])
@handle_errors
def login():
    token = request.form.get('token')
    password = request.form.get('password')

    data, return_url = authenticate(token)
    email, user, registered = login_data(data)

    user_data = verify_password(user, password)
    register_user(
            email,
            firstname=str(user_data['givenName']),
            lastname=str(user_data['sn']),
            username=user)
    return redirect(return_url, code=302)
