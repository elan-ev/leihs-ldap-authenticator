import argparse

from leihsldap.config import update_configuration


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='LDAP based authentication handler for Leihs',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-c', '--config',
        type=str,
        default=None,
        help='Path to a configuration file'
    )
    args = parser.parse_args()
    if args.config:
        update_configuration(args.config)

    # Since `app` will use the configuration,
    # load it only after we updated the configuration location
    from leihsldap.web import app
    app.run()
