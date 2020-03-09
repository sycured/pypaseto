#!/usr/bin/env python3
from pendulum import now, parse as pparse

from lib.base64_helpers import b64decode
from lib.decrypt import decrypt
from lib.encrypt import encrypt
from lib.json_helpers import JsonEncoder
from lib.sign import sign
from lib.verify import verify


class PasetoException(Exception):
    pass


class InvalidVersionException(PasetoException):
    pass


class InvalidPurposeException(PasetoException):
    pass


class InvalidTokenException(PasetoException):
    pass


class PasetoValidationError(PasetoException):
    pass


class PasetoTokenExpired(PasetoValidationError):
    pass


DEFAULT_RULES = {'exp'}
inv_purp = 'invalid purpose'


def create(
        key,
        purpose: str,
        claims: dict,
        exp_seconds=None,
        footer=None,
        encoder=JsonEncoder,
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
    :param footer: dict of the footer that will be authenticated but not encrypted
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


def _extract_footer_unsafe(token):
    """
    Gets the footer out of a token. Useful if you need to use the footer to
    determine which key to load up, for example. This is performed on the
    UNVALIDATED FOOTER. So you shouldn't use this in place of actually
    validating the token afterwards:

        token = '...'
        footer = paseto.extract_footer_unvalidated(token)
        # json decode manually here if you need to
        key_id = json.loads(footer)['key_id']
        key = key_system.get_key_by_id(key_id) # fetch the key here
        parsed = paseto.parse(
            key=key,
            purpose='local',
            token=token,
        )

    If for some reason you are putting claims in the footer, do not use this!
    You still need to call "parse" so the signature can be verified.

    You should also never use this function to get the key itself out of the
    footer. Even if the key is the public key, you should NEVER load a key
    out of the footer through this function. It is only suitable to read a
    key-id from the footer, and to then perform a lookup to find the right key.

    :param token:
    :return:
    """
    parts = token.split(b'.')
    if len(parts) < 4:
        return None
    return b64decode(parts[3])


def check_claims(given, required):
    if required:
        missing_claims = set(required).difference(given)
        if missing_claims:
            raise PasetoValidationError(f'required claims missing {missing_claims}')


def parse(
        key,
        purpose: str,
        token: bytes,
        encoder=JsonEncoder,
        validate: bool = True,
        rules=None,
        required_claims=None
):
    """
    Parse a paseto token.
    Takes a key, a purpose (which must be either 'local' or 'public'), and
    a `token`, which must be a bytes object.

    By default, it validates known registered claims (currently just 'exp').
    To disable validation, set "validate" to False. Cryptographic validity
    cannot be turned off (decryption and authentication are still performed).

    You can also turn on/off validation of specific rules by passing a list to
    "rules". If you pass an empty list to "rules", you must also specify
    "validate=False" or it will raise an exception.

    You may pass an alternative encoder if you don't want to use JSON. It
    should have loads/dumps methods available, and output a bytes object (not
    a str).
    :param key: decryption/validation key. Must match the purpose type
    :param purpose: one of 'local', 'public'
    :param token: bytes object with the raw paseto token
    :param encoder: optional encoder to use instead of JSON
    :param validate: bool indicating if claims should be validated with rules
    :param rules: list of rule names to apply to override the default rules
    :param required_claims: list of claim names that must be present (like exp)
    :return:
    """
    if purpose not in {'local', 'public'}:
        raise InvalidPurposeException(inv_purp)
    if not key:
        raise ValueError('key is required')
    if purpose == 'local':
        result = decrypt(token, key)
    else:
        result = verify(token, key)
    decoded_message = encoder.loads(result['message'])
    decoded_footer = encoder.loads(result['footer']) if result['footer'] else None

    check_claims(set(decoded_message.keys()), required_claims)

    rules = DEFAULT_RULES if not rules else set(rules)
    if validate and not rules:
        raise ValueError('must set validate=False to use no rules')

    rule_set = {'exp'}
    unknown_rules = rules.difference(rule_set)
    if unknown_rules:
        raise ValueError(f'unknown rules: {unknown_rules}')

    if validate and 'exp' in rules and 'exp' in decoded_message:
        # validate expiration
        exp = decoded_message['exp']
        when = pparse(exp)
        if now() > when:
            raise PasetoTokenExpired('token expired')
    return {'message': decoded_message, 'footer': decoded_footer}
