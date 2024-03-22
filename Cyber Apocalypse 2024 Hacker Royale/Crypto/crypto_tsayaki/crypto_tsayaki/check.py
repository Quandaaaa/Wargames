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

c = bytes.fromhex("8c0acbde4a1af63579313db874ab79a991fbaad4a459e4a5")
key = bytes.fromhex("9d6e095e19614e4f0bade6546f99d105")
msg = bytes.fromhex("0bc8f872e85a549c9815e69e1be5774631837362")
cipher = Cipher(key)
from pwn import xor
block1 = cipher.decrypt(c[:8])
iv = xor(block1, msg[:8])
print(iv)

# key = bytes.fromhex("850c1413787c389e0b34437a6828a1b2")
# cipher = Cipher(key)
# Ciphertext = "b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843"
# c = bytes.fromhex(Ciphertext)
# ct = cipher.decrypt(c)

# print(ct)