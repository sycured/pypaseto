#!/usr/bin/env python3
from lib.create import create as lcreate
from lib.decrypt import decrypt as ldecrypt
from lib.encrypt import encrypt as lencrypt
from lib.json_helpers import JsonEncoder
from lib.parse import parse as lparse
from lib.sign import sign as lsign
from lib.utils import extract_footer_unsafe as lextract_footer_unsafe
from lib.verify import verify as lverify


def create(key, purpose: str, claims: dict, exp_seconds=None, footer=None,
           encoder=JsonEncoder):
    lcreate(key, purpose, claims, exp_seconds, footer, encoder)


def decrypt(cls, token: bytes, key: bytes):
    ldecrypt(cls, token, key)


def encrypt(cls, plaintext: bytes, key: bytes, footer=b''):
    lencrypt(cls, plaintext, key, footer)


def extract_footer_unsafe(token):
    lextract_footer_unsafe(token)


def parse(key, purpose: str, token: bytes, encoder=JsonEncoder,
          validate: bool = True, rules=None, required_claims=None):
    lparse(key, purpose, token, encoder, validate, rules,
           required_claims)


def sign(cls, data, key, footer=b''):
    lsign(cls, data, key, footer)


def verify(cls, token, key):
    lverify(cls, token, key)
