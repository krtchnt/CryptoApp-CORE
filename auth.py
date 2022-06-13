import os
import secrets
import typing as t
import base64 as b64

from cryptography.hazmat.primitives import hashes as hsh


class AuthenticationError(Exception):
    pass


hash_algo: t.Final = hsh.SHA3_256()

hash_algos: t.Final[dict[str, hsh.HashAlgorithm]] = {
    'sha1': hsh.SHA1(),
    'sha512-224': hsh.SHA512_224(),
    'sha512-256': hsh.SHA512_224(),
    'sha224': hsh.SHA224(),
    "sha256": hsh.SHA256(),
    'sha384': hsh.SHA384(),
    'sha512': hsh.SHA512(),
    'sha3-224': hsh.SHA3_224(),
    "sha3-256": hsh.SHA3_256(),
    'sha3-384': hsh.SHA3_384(),
    'sha3-512': hsh.SHA3_512(),
    'shake128': hsh.SHAKE128(128),
    'shake256': hsh.SHAKE256(128),
    'md5': hsh.MD5(),
    'blake2b': hsh.BLAKE2b(64),
    'blake2s': hsh.BLAKE2s(32),
    'sm3': hsh.SM3(),
}
pepper: t.Final[str] = os.environ.get('CRYPTOAPP_PEPPER', '')


def hash_64(data_bytes: bytes, /, hash_algo_: hsh.HashAlgorithm = hash_algo):
    hashed_bytes = hsh.Hash(hash_algo_)
    hashed_bytes.update(data_bytes)
    b64_bytes = b64.b64encode(hashed_bytes.finalize())
    hashed_data = b64_bytes.decode('ascii')
    return hashed_data


def hash_b64_password(
    password: str, /, hash_algo: hsh.HashAlgorithm = hash_algo
) -> str:
    pwd_bytes = password.encode('utf-8')
    return hash_64(pwd_bytes, hash_algo)


def finalize_password(password: str, /, hash_algo_: hsh.HashAlgorithm) -> str:
    salt = secrets.token_urlsafe(64)
    hashed_pwd = hash_b64_password(pepper + salt + password, hash_algo_)
    hash_algo_name = hash_algo_.name
    return f"{hash_algo_name}${salt}${hashed_pwd}"


def verify_password(user_data: dict[str, t.Any], password: str) -> None:
    hash_algo_name, salt, hashed_pwd = user_data['password'].split('$')
    hash_algo = hash_algos[hash_algo_name]
    h = hash_b64_password(pepper + salt + password, hash_algo)

    if not secrets.compare_digest(hashed_pwd, h):
        raise AuthenticationError
