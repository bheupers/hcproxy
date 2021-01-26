import argparse

from main import get_password_hash

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='password')
    parser.add_argument(
        'password',
        nargs=1,
        help='password to hash'
    )
    args = parser.parse_args()
    print(get_password_hash(args.password[0]))
