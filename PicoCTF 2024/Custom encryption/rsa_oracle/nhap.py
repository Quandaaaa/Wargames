from pwn import*
from Crypto.Util.number import*
N = 5507598452356422225755194020880876452588463543445995226287547479009566151786764261801368190219042978883834809435145954028371516656752643743433517325277971

flag_enc = 2336150584734702647514724021470643922433811330098144930425575029773908475892259185520495303353109615046654428965662643241365308392679139063000973730368839
e = 65537

i = 1
io = remote("titan.picoctf.net", 56147)
io.recvuntil(b'decrypt. \n')
lower_limit = 0
upper_limit = N
while i <= 1024:
    io.sendline(b'd')
    io.recvuntil(b'Enter text to decrypt: ')
    chosen_ct = (((flag_enc)*pow(2**i, e, N)) % N)
    print(chosen_ct)
    io.sendline(str(chosen_ct).encode())
    io.recvuntil(b'decrypted ciphertext as hex (c ^ d mod n): ')
    output = io.recvuntil(b'\n',drop=True).decode()
    print(output)
    if ord(output[-1]) == 0:
        upper_limit = (upper_limit + lower_limit)//2
    elif ord(output[-1]) == 1:
        lower_limit = (lower_limit + upper_limit)//2
    else:
        pass
    i += 1
    if (upper_limit - lower_limit) < 65537:
        print(int(upper_limit),int(lower_limit))
        break
io.interactive()