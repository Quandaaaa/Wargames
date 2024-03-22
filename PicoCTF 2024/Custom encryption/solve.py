a = 95
b = 21
cipher = [237915, 1850450, 1850450, 158610, 2458455, 2273410, 1744710, 1744710, 1797580, 1110270, 0, 2194105, 555135, 132175, 1797580, 0, 581570, 2273410, 26435, 1638970, 634440, 713745, 158610, 158610, 449395, 158610, 687310, 1348185, 845920, 1295315, 687310, 185045, 317220, 449395]

p = 97
g = 31
key = pow(g, a*b, p)
text_key = 'trudeau'
def decrypt(cipher, key):
    semi_cipher = []
    for i in cipher:
        semi_cipher.append((i // (311*key)))
    return semi_cipher

def dynamic_xor_decrypt(semi_cipher, text_key):
    plain_text = ""
    key_length = len(text_key)
    for i, c in enumerate(semi_cipher):
        key_char = text_key[i % key_length]
        char = chr(c ^ ord(key_char))
        plain_text += char
    return plain_text[::-1]

# def dynamic_xor_decrypt(plaintext, text_key):
#     cipher_text = ""
#     key_length = len(text_key)
#     for i, char in enumerate(plaintext[::-1]):
#         key_char = text_key[i % key_length]
#         encrypted_char = chr(ord(char) ^ ord(key_char))
#         cipher_text += encrypted_char
#     return cipher_text

semi_cipher = decrypt(cipher, key)
plaintext = dynamic_xor_decrypt(semi_cipher, text_key)
print(plaintext)