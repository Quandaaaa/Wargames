from pwn import *
from Crypto.Util.number import *
from sage.all import *
from gmpy2 import *
io = remote("challenge.nahamcon.com",  31591)


C = []
N = []
for i in range(4):
    io.recvuntil(b'> ')
    io.sendline(b'1')
    io.recvuntil(b'Enter a message, and the server will encrypt it with a random N!\n> ')
    io.sendline(chr(2).encode())
    io.recvuntil(b'> ')
    N.append(int(io.recvuntil(b'\n')[:-1]))
    io.recvuntil(b'Your encrypted message:')
    io.recvuntil(b'> [')
    C.append(int(io.recvuntil(b']')[:-1]))

K = crt(C, N)
e = int(K.log(2))
N = []
C = []
for i in range(4):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'Your randomly chosen N:')
    io.recvuntil(b'> ')
    N.append(int(io.recvuntil(b'\n')[:-1]))
    io.recvuntil(b'Your encrypted message:')
    io.recvuntil(b'> ')
    C.append(eval(io.recvuntil(b'\n')[:-1]))

print(N)
flag = ""
for i in range(len(C[0])):
    
    tmp = crt([C[_][i] for _ in range(4)], N)
    flag += chr(iroot(tmp, e)[0])
    print(flag)
