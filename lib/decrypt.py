from secrets import compare_digest

from pysodium import crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, \
    crypto_aead_xchacha20poly1305_ietf_decrypt

from lib.base64_helpers import b64decode
from lib.utils import pre_auth_encode


class PasetoException(Exception):
    pass


class InvalidVersionException(PasetoException):
    pass


class InvalidPurposeException(PasetoException):
    pass


def decrypt(cls, token: bytes, key: bytes) -> dict:
    parts = token.split(b'.')
    footer = b''
    if len(parts) == 4:
        encoded_footer = parts[-1]
        footer = b64decode(encoded_footer)
    header_len = len(cls.local_header)
    header = token[:header_len]
    token_version = token[:2]
    if not compare_digest(token_version, cls.version):
        raise InvalidVersionException('not a v2 token')
    if not compare_digest(header, cls.local_header):
        raise InvalidPurposeException('not a v2.local token')
    decoded = b64decode(parts[2])
    nonce = decoded[:crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
    ciphertext = decoded[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:]
    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext=ciphertext,
        ad=pre_auth_encode(header, nonce, footer),
        nonce=nonce,
        key=key
    )
    return {
        'message': plaintext,
        'footer': footer if footer else None
    }
