from util import *
import math

# Generate a (public,private) RSA key pair
def gen_key_pair():
    p = gen_prime(64)
    q = gen_prime(64)
    n = p * q
    totient = ctf(p, q)
    e = (2 ** 16) + 1
    while gcd(totient, e) != 1:
        e += 2
    d = mod_inverse(e, totient)
    print(f"n:{int_size(n)},e:{int_size(e)},d:{int_size(d)}")
    return ((n,e),(n,d))

def byte_encode_public(public):
    n, e = public
    _n = n.to_bytes(128, "big")
    _e = e.to_bytes(4, "big")
    return _n + _e

def byte_encode_private(private):
    n, d = public
    _n = n.to_bytes(128, "big")
    _d = d.to_bytes(128, "big")
    return _n + _d

def byte_decode_public(public):
    _n = public[:128]
    _e = public[128:]
    n = int.from_bytes(_n, "big")
    e = int.from_bytes(_e, "big")
    return (n, e)

def byte_decode_private(private):
    _n = private[:128]
    _d = private[128:]
    n = int.from_bytes(_n, "big")
    d = int.from_bytes(_d, "big")
    return (n, d)

# Encrypt a string using an RSA public key, of the form (n, e)
def encrypt(message, public):
    n, e = public
    if type(message) == str:
        m = pad(message)
    else:
        m = int.from_bytes(message, "big")
    m = pow(m, e, n)
    return m.to_bytes(int_size(m), "big")

# Decrypt an encrypted string using an RSA private key of the form (n, d)
def decrypt(cipher, private):
    m = int.from_bytes(cipher, "big")
    n, d = private
    m = pow(m, d, n)
    return m.to_bytes(int_size(m), "big")