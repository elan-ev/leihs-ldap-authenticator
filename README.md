# Leihs LDAP Authenticator

[![GPLv3+ license](https://img.shields.io/github/license/elan-ev/leihs-ldap-authenticator)
](https://github.com/elan-ev/leihs-ldap-authenticator/blob/main/LICENSE)
[![PyPI](https://img.shields.io/pypi/v/leihs-ldap-authenticator?color=blue)
](https://pypi.org/project/leihs-ldap-authenticator/)
![Status: Beta](https://img.shields.io/badge/status-beta-yellow)

LDAP based authentication handler for [Leihs](https://github.com/leihs/leihs).

![Leihs Login Process](leihs-ldap-login.gif)

## Features

- Provides __LDAP authentication__ for [Leihs](https://github.com/leihs/leihs) 6.x.

  When users want to log in, Leihs will redirect them to this authentication handler where they can authenticate themselves using an LDAP backend

- Automatically __create new users__ in Leihs when they first log in.

  When logging in, users must be registered with Leihs.
  The LDAP authenticator takes care of this automatically when the user first logs in.

- Register or log-in __via email address or username__.

  Users can log in via username or email address.
  For technical details about how LDAP users are mapped, see [LDAP Username Mapping](#ldap-username-mapping) below.

- Automatic __group assignment__ based on LDAP attributes.

  When creating the users, they can be assigned to groups in Leihs based on their LDAP attributes. Groups will be automatically created if they do not yet exist.

- Provides __automatic configuration__ of the Leihs authentication system.

  The authenticator will automatically register itself in Leihs.

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

	The tool should automatically register itself in Leihs.

### Development Version

If you want to work with the development version instead,
you can just clone this repository, install the requirements
and run the project from the root repository path:

```
❯ pip install -r requirements.txt
❯ python -m leihsldap
 * Serving Flask app 'leihsldap.web'
 * Debug mode: off
 * Running on http://127.0.0.1:5000
```

## Production Deployment

While you can just start and test the authenticator with the built-in web server,
using this is _not_ safe for production.
For a production deployment, use a WSGI server like [Gunicorn](https://gunicorn.org/).
A basic example of running this application with Gunicorn is:

```
❯ gunicorn --config=/path/to/gunicorn.conf.py leihsldap.web:app
```

For a systemd unit to turn leisldap into a service and for an example Gunicorn configuration file, take a look at the `init` folder:

- Example [systemd unit](init/leihsldap.service)
- Example [Gunicorn configuration](init/gunicorn.conf.py)

## Technical Notes

### LDAP Username Mapping

If a user does not yet exist in Leihs, the system will always transfer the user input as an email address to the authenticator, regardless of it actually being a valid email address.

To circumvent this, the authenticator will treat the input up to the first `@` character as username and use this for the LDAP login.

Once registered, Leihs will also transfer the login field which is used from there on for authentication.

### Update of Data in Leihs

As a general rule, the authenticator will only ever create,
but never update data in Leihs.
If you want updated data in Leihs,
either update this manually,
or remove the resource to have it recreated with new data.

This applies to:

- Authentication system
- Groups
- Users

This also means that you can update data if you need to.
For example, you can add users to additional groups without the authentication system interfering (potentially removing them again).

## Support

This project is free software. It was initially developed by [ELAN e.V.](https://elan-ev.de) for [Osnabrück University](https://uos.de). We hope that this is helpful, and you can use this as well.

If you need commercial support installing this tool or want to commission further development you aren't able to do yourself, please [contact the ELAN e.V.](https://elan-ev.de)

## Development

To cut a new release:

1. Update the version in [setup.py](setup.py), commit changes, create pull request and merge
1. Update the `main` branch locally and create a release tag: `git tag -s v0.4`
1. Push the tag upstream: `git push upstream v0.4:v0.4`
1. Create a [new release on GitHub](https://github.com/elan-ev/leihs-ldap-authenticator/releases/new).
1. Build Python package and upload it to [pypi.org](https://pypi.org): `python setup.py sdist; twine upload dist/leihs-ldap-authenticator-0.2.tar.gz`
