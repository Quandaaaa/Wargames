from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, long_to_bytes
from hashlib import sha256

p = 0xdd6cc28d
f = GF(p)
g = 0x83e21c05
g = f(g)
A = 0xcfabb6dd
A = f(A)
B = 0xc4a21ba9
B = f(B)
b = discrete_log(B, g)

s = pow(A, b, p)
s = int(s)
ciphertext = b"\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{"



hash = sha256()
hash.update(long_to_bytes(s))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

plaintext = cipher.decrypt(ciphertext)

print(plaintext)