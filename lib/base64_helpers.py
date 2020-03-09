from base64 import urlsafe_b64decode, urlsafe_b64encode


def b64encode(data):
    return urlsafe_b64encode(data).rstrip(b'=')


def b64decode(data):
    return urlsafe_b64decode(data + b'=' * (-len(data) % 4))
