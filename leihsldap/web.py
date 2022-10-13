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

import glob
import logging
import os
import yaml

from flask import Flask, request, redirect, render_template
from functools import wraps
from jwt.exceptions import DecodeError, ExpiredSignatureError
from ldap3.core.exceptions import LDAPBindError, LDAPPasswordIsMandatoryError

from leihsldap.authenticator import response_url, token_data
from leihsldap.config import config
from leihsldap.ldap import ldap_login
from leihsldap.leihs_api import register_user, register_auth_system

# Logger
logger = logging.getLogger(__name__)

flask_config = {}
if config('ui', 'directories', 'template'):
    flask_config['template_folder'] = config('ui', 'directories', 'template')
if config('ui', 'directories', 'static'):
    flask_config['static_folder'] = config('ui', 'directories', 'static')
app = Flask(__name__, **flask_config)

__error = {}
__i18n = {}
__languages = []


def error(error_id: str, code: int) -> tuple[str, int]:
    '''Generate error page based on data defined in `error.yml` and the given
    error identifier.

    :param error_id: String identifying the error to render.
    :param code: HTTP status code to return.
    :returns: Tuple of data for Flask response
    '''
    lang = request.accept_languages.best_match(__languages)
    logger.debug('Using language: %s', lang)
    error_data = __error[lang][error_id].copy()
    error_data['leihs_url'] = config('leihs', 'url')
    error_data['i18n'] = __i18n[lang]
    return render_template('error.html', **error_data), code


def handle_errors(function):
    '''Decorator handling common errors.
    This will cause an errpr page to be rendered.

    :param function: Function to wrap.
    '''
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except DecodeError as e:
            logger.info('Error decoding token: %s', e)
            return error('invalid_token', 400)
        except ExpiredSignatureError as e:
            logger.info('Token expired: %s', e)
            return error('expired_token', 400)
        except (LDAPBindError, LDAPPasswordIsMandatoryError) as e:
            logger.info('LDAP login failed: %s', e)
            return error('invalid_credentials', 403)
    return wrapper


def init():
    '''Load internationalization and try to register the authentication system.
    '''
    # load internationalization data
    files = glob.glob(os.path.dirname(__file__) + '/i18n/error-*.yml')
    globals()['__languages'] = {os.path.basename(f)[6:-4] for f in files}
    logger.info('Detected available languages: %s', __languages)

    for lang in __languages:
        # load error messages
        i18n_file = os.path.dirname(__file__) + f'/i18n/error-{lang}.yml'
        with open(i18n_file, 'r') as f:
            globals()['__error'][lang] = yaml.safe_load(f)

        # load internationalization file
        i18n_file = os.path.dirname(__file__) + f'/i18n/i18n-{lang}.yml'
        with open(i18n_file, 'r') as f:
            globals()['__i18n'][lang] = yaml.safe_load(f)

    # Try to register auth system
    logger.info('Trying to register authentication system')
    register_auth_system()


@app.errorhandler(500)
def internal_server_error(e):
    '''Handle internal server errors.
    This causes the app to render an error page similar to known and caught
    errors.
    '''
    return error('internal', 500)


@app.route('/', methods=['GET'])
@handle_errors
def login_page():
    '''Render login page.
    This is the page users will end up on when redirected from Leihs.
    '''
    token = request.args.get('token')
    if not token:
        logger.debug('No token provided')
        return error('no_token', 400)
    _, email, user, _ = token_data(token)
    i18n = __i18n[request.accept_languages.best_match(__languages)()]
    return render_template('login.html', token=token, user=user, i18n=i18n)


@app.route('/', methods=['POST'])
@handle_errors
def login():
    '''Handle login POST requests.
    The POST request form data must contain the fields:

    - token: JWT token received from and signed by Leihs
    - password: The password the user tries to sign in with
    '''
    # get form data
    token = request.form.get('token')
    password = request.form.get('password')

    # verify token and get login data
    data, email, user, registered = token_data(token)

    # Login to and get user data from LDAP
    user_data = ldap_login(user, password)

    # Get list of groups the user should be in
    group_fields = config('ldap', 'userdata', 'groups', 'fields') or []
    groups = [group for field in group_fields for group in user_data[field]]

    # Check if to fall back to the LDAP email address
    email_overwrite = config('ldap', 'userdata', 'email', 'overwrite')
    email_fallback = config('ldap', 'userdata', 'email', 'fallback')
    email_invalid = not email or '@' not in email
    if email_overwrite or email_fallback and email_invalid:
        email_field = config('ldap', 'userdata', 'email', 'field')
        email = user_data[email_field][0]
        data['email'] = email

    # Make sure user is registered with Leihs
    register_user(
            email,
            firstname=user_data['givenName'][0],
            lastname=user_data['sn'][0],
            username=user,
            groups=groups)

    # Redirect back to Leihs with success token
    return redirect(response_url(token, data), code=302)


init()
