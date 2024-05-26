import hashlib
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
 # I'll use my own library for this
from base64 import b64decode
import os
from Crypto.Util.number import getPrime

def decrypt_flag(shared_secret: int, ciphertext: str):
    iv = b64decode("MWkMvRmhFy2vAO9Be9Depw==")

    #get AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    #encrypt flag
    ciphertext = pad(b64decode(ciphertext), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext

print(decrypt_flag(130102914376597655583988556541378621904, "SllGMo5gxalFG9g8j4KO0cIbXeub0CM2VAWzXo3nbIxMqy1Hl4f+dGwhM9sm793NikYA0EjxvFyRMcU2tKj54Q=="))

#byuctf{mult1pl1c4t10n_just_g0t_s0_much_m0r3_c0mpl1c4t3d}