from pysodium import crypto_sign_detached

from lib.base64_helpers import b64encode
from lib.utils import pre_auth_encode


def sign(cls, data, key, footer=b''):
    signature = crypto_sign_detached(
        m=pre_auth_encode(cls.public_header, data, footer),
        sk=key
    )
    token = cls.public_header + b64encode(data + signature)
    if footer:
        token += b'.' + b64encode(footer)
    return token
