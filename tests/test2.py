def main():
    import dotenv

    from crypto_app_core import auth as au

    dotenv.load_dotenv()  # pyright: reportUnknownMemberType=false

    p = 'password123'

    _p = au.finalize_password(p, au.hash_algo)

    print(_p)

    user = {'password': _p}

    au.verify_password(user, p)


if __name__ == '__main__':
    main()
