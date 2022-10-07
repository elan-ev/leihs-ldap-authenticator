import multiprocessing
from leihsldap.config import update_configuration

# Gunicorn configuration for Leihs LDAP Authenticator
#
# For details of the available options see:
# https://docs.gunicorn.org/en/stable/settings.html#settings

# The socket to bind.
# This can be a TCP socket:
#   bind = "127.0.0.1:8000"
# …or a UNIX socket:
#   bind = "unix:/var/run/pyca/uisocket"
#
# Default: "127.0.0.1:8000"
#bind = "127.0.0.1:8000"

# The number of worker processes for handling requests.
# Default: 1
workers = multiprocessing.cpu_count()

# Load the leihsldap configuration file from a custom location.
#
# By default, leihsldap will try loading configuration from the following
# locations, stopping once it found a configuration file:
# - ./leihs-ldap.yml
# - ~/leihs-ldap.yml
# - /etc/leihs-ldap.yml
#
#update_configuration('/path/to/leihs-ldap.yml')
