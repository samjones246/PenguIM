from util import bytes_xor, chunk_bytes, rotr
from functools import reduce
import os

k = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]

def hmac(message, key):
    h = sha2
    if len(key) > 64:
        key = h(key)
    
    if len(key) < 64:
        key += bytes([0] * (64 - len(key)))

    opad = bytes([0x5c] * 64)
    ipad = bytes([0x36] * 64)

    return h(bytes_xor(key, opad) + h(bytes_xor(key, ipad) + message))

def sha2(message):
    hvals = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    ]
    inlen = (len(message) * 8).to_bytes(8, "big")
    message += bytes([0x80])
    if len(message) % 64 != 56:
        padlen = 56 - (len(message) % 64)
        message += bytes([0] * padlen)
    message += inlen
    for bstart in range(0, len(message), 64):
        w = [int.from_bytes(x, "big") for x in chunk_bytes(message[bstart:bstart+64])]
        w += [0] * 48
        for i in range(16, 64):
            s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) % (2**32)
        a, b, c, d, e, f, g, h = hvals
        for i in range(64):
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
            temp1 = (h + s1 + ch + k[i] + w[i]) % (2 ** 32)
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) % (2**32)
            h = g
            g = f
            f = e
            e = (d + temp1) % (2**32)
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % (2**32)
        tempvals = [a,b,c,d,e,f,g,h]
        for i in range(8):
            hvals[i] = (hvals[i] + tempvals[i]) % (2**32)
    out = [b.to_bytes(4, "big") for b in hvals]
    return reduce(lambda a,b:a+b,out,bytes())

def gen_key():
    return os.urandom(32)

def verify(message, key, mac):
    return mac == hmac(message, key)
