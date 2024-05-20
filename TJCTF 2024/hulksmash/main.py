from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

keys = open("keysmashes.txt", "rb").read().split(b'\n')[:-1]
print(keys)
# flag = pad(open("flag.txt", "rb").read(), 16)
for key in keys:
    c = bytes.fromhex("ed05f1440f3ae5309a3125a91dfb0edef306e1a64d1c5f7d8cea88cdb7a0d7d66bb36860082a291138b48c5a6344c1ab")
    cipher = AES.new(key, AES.MODE_ECB)
    print(cipher.decrypt(c))
