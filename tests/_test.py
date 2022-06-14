from cryptography.hazmat.primitives.asymmetric import padding as pdd, rsa
from cryptography.hazmat.primitives import serialization as srz
from cryptography.hazmat.primitives import hashes as hsh

pwd = b'HMt6X4EotcG3t^9@'

sk = rsa.generate_private_key(65537, key_size=2048)
pk = sk.public_key()

pk_pem = pk.public_bytes(srz.Encoding.PEM, format=srz.PublicFormat.SubjectPublicKeyInfo)
sk_pem = sk.private_bytes(
    srz.Encoding.PEM,
    format=srz.PrivateFormat.PKCS8,
    encryption_algorithm=srz.BestAvailableEncryption(pwd),
)

msg = b"A message I want to sign"
sig = sk.sign(
    msg,
    pdd.PSS(mgf=pdd.MGF1(hsh.SHA256()), salt_length=pdd.PSS.MAX_LENGTH),
    hsh.SHA256(),
)

pk.verify(
    sig,
    msg,
    pdd.PSS(mgf=pdd.MGF1(hsh.SHA256()), salt_length=pdd.PSS.MAX_LENGTH),
    hsh.SHA256(),
)
