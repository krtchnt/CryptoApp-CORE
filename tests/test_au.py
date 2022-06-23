import dotenv

import pytest

from crypto_app_core import auth as au


def _test_auth(p: str, q: str, /):
    dotenv.load_dotenv()  # pyright: reportUnknownMemberType=false

    _p = au.finalize_password(p, au.hash_algo)
    print(_p)

    user = {'password': _p}
    au.verify_password(user, q)


def _test_auth_xfail(p: str, q: str, /):
    dotenv.load_dotenv()  # pyright: reportUnknownMemberType=false

    _p = au.finalize_password(p, au.hash_algo)
    user = {'password': _p}
    with pytest.raises(au.AuthenticationError):
        au.verify_password(user, q)


@pytest.mark.parametrize(
    ('sign_in_pwd', 'sign_up_pwd'),
    (
        ('pw', 'pw'),
        ('password123', 'password123'),
        (
            'suY*2PTVD&t5rDhTelg#my6VaFqKSGEe%9N^We%%atx%8LFy#QR64#OhW@U1NcT1EN%pb59BjYRXK28@@3rLnUxGcIw&cGhAAtR2r!AdJJBDanmjwkEmIxl!qlroEZxX',
            'suY*2PTVD&t5rDhTelg#my6VaFqKSGEe%9N^We%%atx%8LFy#QR64#OhW@U1NcT1EN%pb59BjYRXK28@@3rLnUxGcIw&cGhAAtR2r!AdJJBDanmjwkEmIxl!qlroEZxX',
        ),
    ),
)
def test_auths(sign_in_pwd: str, sign_up_pwd: str):
    _test_auth(sign_in_pwd, sign_up_pwd)


@pytest.mark.parametrize(
    ('sign_in_pwd', 'sign_up_pwd'),
    (
        ('pw', 'pd'),
        ('password123', 'password122'),
        (
            'suY*2PTVD&t5rDhTelg#my6VaFqKSGEe%9N^We%%atx%8LFy#QR64#OhW@U1NcT1EN%pb59BjYRXK28@@3rLnUxGcIw&cGhAAtR2r!AdJJBDanmjwkEmIxl!qlroEZxX',
            'suY*2PTVD&t5rDhTelg#my6VaFqKSGEe%9N^We%%atx%8LFy#QR64#OhW@U1NcT1EN%pb59BjYRXK28@@3rLnUxGcIw&cGhAAtR2r!AdJJBDanmjwkEmIxl!qlroEZxY',
        ),
    ),
)
def test_auths_xfail(sign_in_pwd: str, sign_up_pwd: str):
    _test_auth_xfail(sign_in_pwd, sign_up_pwd)
