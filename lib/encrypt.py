from pysodium import crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, \
    crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_generichash, randombytes

from lib.base64_helpers import b64encode
from lib.utils import pre_auth_encode
from lib import consts


def encrypt(
        plaintext: bytes,
        key: bytes,
        footer=b''
) -> bytes:
    nonce_key = randombytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    nonce = crypto_generichash(
        plaintext,
        k=nonce_key,
        outlen=crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    )
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=plaintext,
        ad=pre_auth_encode(consts.local_header, nonce, footer),
        nonce=nonce,
        key=key
    )
    token = consts.local_header + b64encode(nonce + ciphertext)
    if footer:
        token += b'.' + b64encode(footer)
    return token
