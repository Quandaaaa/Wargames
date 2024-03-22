import os
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)

    def decrypt_block(self, ct):
        c0 = b2l(ct[:4])
        c1 = b2l(ct[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0xC6EF3720
        for i in range(32):
            c1 -= ((c0 << 4) + K[2]) ^ (c0 + s) ^ ((c0 >> 5) + K[3])
            c1 &= msk
            c0 -= ((c1 << 4) + K[0]) ^ (c1 + s) ^ ((c1 >> 5) + K[1]) 
            c0 &= msk
            s -= self.DELTA

        c = ((c0 << (self.BLOCK_SIZE//2)) + c1) & ((1 << self.BLOCK_SIZE) - 1)

        return l2b(c)

    def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]

        msg = b''
        if self.mode == Mode.ECB:
            for ct in blocks:
                msg += self.decrypt_block(ct)
        elif self.mode == Mode.CBC:
            X = self.IV
            for ct in blocks:
                msg += self._xor(self.decrypt_block(ct), X)
                X = ct        
        return msg
    

from pwn import remote, xor
import os

CONST = bytes.fromhex("80000000")
IV = b'\r\xdd\xd2w<\xf4\xb9\x08'

def gen_key():
    keys = []
    key = os.urandom(16)
    key1, key2, key3, key4 = [key[i:i+4] for i in range(0, 16, 4)]
    keys = [
        b''.join([key1, key2, key3, key4]),
        b''.join([key1, key2, xor(key3, CONST), xor(key4, CONST)]),
        b''.join([xor(key1, CONST), xor(key2, CONST), key3 , key4 ]),
        b''.join([xor(key1, CONST), xor(key2, CONST), xor(key3, CONST), xor(key4, CONST)])
    ]
    return keys
    
io = remote('83.136.254.223', 32915)

io.recvuntil(b'Here is my special message:')
server_message = io.recvuntil(b'\n', drop = True).decode()

def payload(key):
    cipher = Cipher(key, IV)
    enc = cipher.encrypt(bytes.fromhex(server_message))
    return enc.hex()

for i in range(10):
    keys = gen_key()
    io.recvuntil(b'Enter your target ciphertext (in hex) : ')
    io.sendline(payload(keys[0]).encode())
    for key in keys:
        
        io.recvuntil(b'Enter your encryption key (in hex) : ')
        io.sendline(key.hex().encode())
    
io.recvlines()
        