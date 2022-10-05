# leihs-ldap-authenticator

[![GPLv3+ license](https://img.shields.io/github/license/elan-ev/leihs-ldap-authenticator)
](https://github.com/elan-ev/leihs-ldap-authenticator/blob/main/LICENSE)
[![PyPI](https://img.shields.io/pypi/v/leihs-ldap-authenticator?color=blue)
](https://pypi.org/project/leihs-ldap-authenticator/)
![Status: Beta](https://img.shields.io/badge/status-neta-yellow)

LDAP based authentication handler for [Leihs](https://github.com/leihs/leihs).

## Getting Started

1. Install the tool via pip:
	```
	❯ pip install leihs-ldap-authenticator
	```
2. Download and edit the [example configuration](https://github.com/elan-ev/leihs-ldap-authenticator/blob/main/leihs-ldap.yml).
   The configuration keys are documented in the file:
	```
	❯ wget https://github.com/elan-ev/leihs-ldap-authenticator/blob/main/leihs-ldap.yml
	```
3. Run the tool:
   ```
	❯ python -m leihsldap -c /path/to/leihs-ldap.yml
   ```

### Development Version

If you want to work with the development version instead,
you can just clone this repository, install the requirements
and run the project from the root repository path:

```
❯ pip install -r requirements.txt
❯ python -m leihsldap
 * Serving Flask app 'leihsldap.web'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
```
