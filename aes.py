from math import log
from util import table_2, table_3, table_9, table_11, table_13, table_14
from util import bytes_xor, chunk_bytes as chunk_key
import os
sbox = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B,0x36]

def gen_key():
    return os.urandom(16)

def expand_key(key):
    global rcon
    N = len(key) // 4
    K = chunk_key(key)
    R = [11,13,15][(N//2) - 2]
    W = []
    for i in range(4*R):
        if i < N:
            W.append(K[i])
        else:
            if i % N == 0:
                a = bytes_xor(W[i-N], sub_word(rot_word(W[i-1])))
                b = bytes([rcon[(i // N) - 1],0,0,0])
                W.append(bytes_xor(a, b))
            elif N > 6 and i % N == 4:
                W.append(bytes_xor(W[i-N],sub_word(W[i-1])))
            else:
                W.append(bytes_xor(W[i-N],W[i-1]))
    out = []
    rkey = bytes([])
    for i in range(len(W)):
        rkey += W[i]
        if len(rkey) == 16:
            out.append(rkey)
            rkey = bytes([])
    return out

def rot_word(w):
    return w[1:] + bytes([w[0]])

def sub_word(w):
    global sbox
    return bytes([sbox[b] for b in w])

def encrypt_block(message, key):
    ekey = expand_key(key)
    if type(message) == str:
        state = message[:16].encode("utf-8")
    else:
        state = message[:16]
    state = add_round_key(state, ekey[0])
    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, ekey[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, ekey[-1])
    return bytes(state)


def add_round_key(state, rkey):
    out = []
    for i in range(len(state)):
        out.append(state[i] ^ rkey[i])
    return out

def sub_bytes(state):
    global sbox
    return [sbox[b] for b in state]

def shift_rows(state):
    out = [0] * 16
    shift = 0
    for i in range(4):
        row = [state[(j*4) + i] for j in range(4)]
        shifted = row[shift:] + row[:shift]
        out[i] = shifted[0]
        out[4+i] = shifted[1]
        out[8+i] = shifted[2]
        out[12+i] = shifted[3]
        shift += 1
    return out

def mix_columns(state):
    out = []
    for i in range(0, 16, 4):
        column = state[i:i+4]
        mixed = mix_column(column)
        out += mixed
    return out

def mix_column(c):
    out = [0] * 4
    out[0] = table_2[c[0]] ^ table_3[c[1]] ^ c[2] ^ c[3]
    out[1] = c[0] ^ table_2[c[1]] ^ table_3[c[2]] ^ c[3]
    out[2] = c[0] ^ c[1] ^ table_2[c[2]] ^ table_3[c[3]]
    out[3] = table_3[c[0]] ^ c[1] ^ c[2] ^ table_2[c[3]]
    return out

def mix_column_alt(r):
    a = [0] * 4
    b = [0] * 4
    out = r[:]
    h = 0
    for c in range(4):
        a[c] = r[c]
        h = (r[c] >> 7) & 1
        b[c] = r[c] << 1
        b[c] ^= h * 0x1B
        b[c] = b[c] % 256
    out[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
    out[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
    out[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
    out[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]
    return out

def inv_sub_bytes(state):
    global sbox
    return [sbox.index(b) for b in state]

def inv_shift_rows(state):
    out = [0] * 16
    shift = 0
    for i in range(4):
        row = [state[(j*4) + i] for j in range(4)]
        shifted = row[-shift:] + row[:-shift]
        out[i] = shifted[0]
        out[4+i] = shifted[1]
        out[8+i] = shifted[2]
        out[12+i] = shifted[3]
        shift += 1
    return out

def inv_mix_columns(state):
    out = []
    for i in range(0, 16, 4):
        column = state[i:i+4]
        mixed = inv_mix_column(column)
        out += mixed
    return out

def inv_mix_column(c):
    out = [0] * 4
    out[0] = table_14[c[0]] ^ table_11[c[1]] ^ table_13[c[2]] ^ table_9[c[3]]
    out[1] = table_9[c[0]] ^ table_14[c[1]] ^ table_11[c[2]] ^ table_13[c[3]]
    out[2] = table_13[c[0]] ^ table_9[c[1]] ^ table_14[c[2]] ^ table_11[c[3]]
    out[3] = table_11[c[0]] ^ table_13[c[1]] ^ table_9[c[2]] ^ table_14[c[3]]
    return out

def cfb_encrypt(m, key, iv=None):
    if iv is None:
        iv = os.urandom(16)
    prev = iv
    out = iv
    for i in range(0, len(m), 16):
        p = m[i:min(i+16,len(m))]
        a = encrypt_block(prev, key)
        c = bytes_xor(p, a)
        prev = c
        out += c
    return out

def cfb_decrypt(c, key):
    iv = c[:16]
    prev = iv
    out = bytes()
    for i in range(16, len(c), 16):
        block = c[i:min(i+16,len(c))]
        a = encrypt_block(prev, key)
        p = bytes_xor(block, a)
        prev = block
        out += p
    return out