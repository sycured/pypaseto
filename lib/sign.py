from pysodium import crypto_sign_detached

from lib.base64_helpers import b64encode
from lib.utils import pre_auth_encode
from lib import consts


def sign(data, key, footer=b''):
    signature = crypto_sign_detached(
        m=pre_auth_encode(consts.public_header, data, footer),
        sk=key
    )
    token = consts.public_header + b64encode(data + signature)
    if footer:
        token += b'.' + b64encode(footer)
    return token
