'''
Load and handle Leihs LDAP Authenticator configuration.
'''

import logging
import os
import yaml

# Logger
logger = logging.getLogger(__name__)

__config = {}


def configuration_file():
    '''Find the best match for the configuration file.  The configuration file
    locations taken into consideration are (in this particular order):

    - ``./leihs-ldap.yml``
    - ``~/leihs-ldap.yml``
    - ``/etc/leihs-ldap.yml``

    :return: configuration file name or None
    '''
    if os.path.isfile('./leihs-ldap.yml'):
        return './leihs-ldap.yml'
    expanded_file = os.path.expanduser('~/leihs-ldap.yml')
    if os.path.isfile(expanded_file):
        return expanded_file
    if os.path.isfile('/etc/leihs-ldap.yml'):
        return '/etc/leihs-ldap.yml'


def update_configuration():
    '''Update configuration.
    '''
    cfgfile = configuration_file()
    if not cfgfile:
        return {}
    with open(cfgfile, 'r') as f:
        cfg = yaml.safe_load(f)
    globals()['__config'] = cfg

    # update logger
    loglevel = cfg.get('loglevel', 'INFO').upper()
    logging.root.setLevel(loglevel)
    logger.info('Log level set to %s', loglevel)

    return cfg


def config(*args):
    '''Get a specific configuration value or the whole configuration, loading
    the configuration file if it was not before.

    :param key: optional configuration key to return
    :type key: string
    :return: dictionary containing the configuration or configuration value
    '''
    cfg = __config or update_configuration()
    for key in args:
        if cfg is None:
            return
        cfg = cfg.get(key)
    return cfg
