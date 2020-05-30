from pendulum import now, parse as pparse

from lib.decrypt import decrypt
from lib.json_helpers import JsonEncoder
from lib.verify import verify


DEFAULT_RULES = {'exp'}
inv_purp = 'invalid purpose'


def check_claims(given, required):
    if required:
        missing_claims = set(required).difference(given)
        if missing_claims:
            raise ValueError(
                f'required claims missing {missing_claims}')


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
        raise ValueError(inv_purp)
    if not key:
        raise ValueError('key is required')
    result = decrypt(token, key) if purpose == 'local' else verify(token, key)
    decoded_message = encoder.loads(result['message'])
    decoded_footer = encoder.loads(result['footer']) if result[
        'footer'] else None

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
            raise ValueError('token expired')
    return {'message': decoded_message, 'footer': decoded_footer}
