from pendulum import now

from lib.encrypt import encrypt
from lib.json_helpers import JsonEncoder
from lib.sign import sign


class PasetoException(Exception):
    pass


class InvalidPurposeException(PasetoException):
    pass


inv_purp = 'invalid purpose'


def create(
        key,
        purpose: str,
        claims: dict,
        exp_seconds=None,
        footer=None,
        encoder=JsonEncoder
):
    """
    Creates a new paseto token using the provided key, purpose, and claims.

    The exp claim is registered. To set it manually, leave the `exp_seconds`
    parameter as None, and manually put it into your claims dict. Otherwise,
    it acts as a number-of-seconds-from-now and is dynamically calculated when
    the token is made.

    You may pass an alternative encoder if you don't want to use JSON. It
    should have loads/dumps methods available, and output a bytes object (not
    a str).
    :param key:
    :param purpose:
    :param claims: dict of the claims to include in the token
    :param exp_seconds: number of seconds from now before expiration
    :param footer: dict of footer that will be authenticated but notencrypted
    :param encoder: encoder to use if you don't want the default JSON encoder
    :return:
    """
    if purpose not in {'local', 'public'}:
        raise InvalidPurposeException(inv_purp)
    if not key:
        raise ValueError('key is required')

    if exp_seconds:
        then = now().add(seconds=exp_seconds).to_atom_string()
        claims['exp'] = then

    encoded = encoder.dumps(claims)
    encoded_footer = encoder.dumps(footer) if footer else b''

    if purpose == 'local':
        token = encrypt(
            plaintext=encoded,
            key=key,
            footer=encoded_footer
        )

    elif purpose == 'public':
        token = sign(
            data=encoded,
            key=key,
            footer=encoded_footer
        )
    else:
        raise InvalidPurposeException(inv_purp)
    return token
