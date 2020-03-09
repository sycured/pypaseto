from secrets import compare_digest

from pysodium import crypto_sign_BYTES, crypto_sign_verify_detached

from lib.base64_helpers import b64decode
from lib.utils import pre_auth_encode


class PasetoException(Exception): pass


class InvalidVersionException(PasetoException): pass


class InvalidPurposeException(PasetoException): pass


class InvalidTokenException(PasetoException): pass


def verify(cls, token, key):
    token_header = token[:len(cls.public_header)]
    token_version = token[:2]
    if not compare_digest(token_version, cls.version):
        raise InvalidVersionException('not a v2 token')
    if not compare_digest(token_header, cls.public_header):
        raise InvalidPurposeException('not a v2.public token')
    parts = token.split(b'.')
    footer = b''
    if len(parts) == 4:
        encoded_footer = parts[-1]
        footer = b64decode(encoded_footer)
    decoded = b64decode(parts[2])
    message = decoded[:-crypto_sign_BYTES]
    signature = decoded[-crypto_sign_BYTES:]
    try:
        crypto_sign_verify_detached(
            sig=signature,
            msg=pre_auth_encode(token_header, message, footer),
            pk=key
        )
    except ValueError as e:
        raise InvalidTokenException('invalid signature') from e
    return {'message': message, 'footer': footer}
