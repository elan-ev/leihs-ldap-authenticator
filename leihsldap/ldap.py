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

import logging

from ldap3 import Server, Connection, ALL, AUTO_BIND_NO_TLS

from leihsldap.config import config

# Logger
logger = logging.getLogger(__name__)


def ldap_login(username: str, password: str) -> dict[str, list]:
    '''Login to LDAP and return user attributes.

    The idea of this is basically for the user to login to LDAP and request its
    own attributes. Obviously, this code will do that for the user with the
    provided credentials.

    :param username: Username to log in with.
    :param password: Password to log in with.
    :returns: Dictionary containing requested user attributes.
    '''
    user_dn = config('ldap', 'user_dn').format(username=username)

    logger.debug('Trying to log into LDAP with user_dn `%s`', user_dn)
    server = Server(config('ldap', 'server'),
                    port=config('ldap', 'port'),
                    use_ssl=True,
                    get_info=ALL)
    # Note: AUTO_BIND_NO_TLS means no Start TLS
    # See: https://github.com/cannatag/ldap3/issues/1061
    conn = Connection(server, user_dn, password, auto_bind=AUTO_BIND_NO_TLS)
    logger.debug('Login successful with user_dn `%s`', user_dn)

    attributes = list(filter(bool, [
        config('ldap', 'userdata', 'email', 'field'),
        config('ldap', 'userdata', 'name', 'family'),
        config('ldap', 'userdata', 'name', 'given')]))
    attributes += config('ldap', 'userdata', 'groups', 'fields') or []

    logger.debug('Searching for user data')
    conn.search(
            config('ldap', 'base_dn'),
            config('ldap', 'search_filter').format(username=username),
            attributes=attributes)
    if len(conn.entries) != 1:
        raise ValueError('Search must return exactly one result', conn.entries)
    logger.debug('Found user data')
    return conn.entries[0].entry_attributes_as_dict
