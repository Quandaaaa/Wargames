from pytea import TEA


key = "850c1413787c389e0b34437a6828a1b2"
key = b''.join([bytes.fromhex(key[i:i+4]) for i in range(0, len(key), 4)])
print(len(key))

Ciphertext : "b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843"
print(bytes.fromhex(Ciphertext))
print(key)
# tea = TEA(key)
# e = tea.decrypt(bytes.fromhex(Ciphertext))

# print(e)
