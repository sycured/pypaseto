import struct

from lib.base64_helpers import b64decode


def pre_auth_encode(*parts):
    accumulator = struct.pack('<Q', len(parts))
    for part in parts:
        accumulator += struct.pack('<Q', len(part))
        accumulator += part
    return accumulator


def extract_footer_unsafe(token):
    """
    Gets the footer out of a token. Useful if you need to use the footer to
    determine which key to load up, for example. This is performed on the
    UNVALIDATED FOOTER. So you shouldn't use this in place of actually
    validating the token afterwards:

        token = '...'
        footer = paseto.extract_footer_unsafe(token)
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
