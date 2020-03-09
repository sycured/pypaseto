import struct


def pre_auth_encode(*parts):
    accumulator = struct.pack('<Q', len(parts))
    for part in parts:
        accumulator += struct.pack('<Q', len(part))
        accumulator += part
    return accumulator
