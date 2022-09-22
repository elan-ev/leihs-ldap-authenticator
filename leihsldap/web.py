from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError
from flask import Flask, request, redirect, render_template_string

from leihsldap.authenticator import authenticate, token_data
from leihsldap.register_user import register_user
from leihsldap.config import config


app = Flask(__name__)

TPL = '''<!doctype html>
<html>
<title>Login</title>
<body style="width: 100px; margin: 100px auto;">
<form action="/" method="POST">
    <input type="hidden" name="token" value="{{ token }}"/>
    <input type="text" name="user" value="{{ user }}" readonly />
    <input type="password" name="password" placeholder="password" autofocus />
    <button type="submit">Login</button>
</form>
</body>
</html>
'''

def ensure_list(var):
    if type(var) is list:
        return var
    return [var]


def verify_password(username, password):
    user_dn = config('ldap', 'user_dn').format(username=username)

    #server = Server('ldap.uni-osnabrueck.de', use_ssl=True, get_info=ALL)
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
        raise ValueError('Search must return exactly one result:', conn.entries)
    return conn.entries[0]


def login_data(token_data):
    email = data.get('email')
    login = data.get('login')
    if login:
        return email, login, True
    login = email.split('@', 1)[0]
    return email, login, False


@app.route('/', methods=['GET'])
def login_page():
    token = request.args.get('token')
    data = token_data(token)
    email, user, _ = login_data(data)
    return render_template_string(TPL, token=token, user=user)


@app.route('/', methods=['POST'])
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
            login=user)
    return redirect(return_url, code=302)
