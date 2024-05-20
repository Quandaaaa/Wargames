from sage.all import *
from Crypto.Util.number import *
from pwn import *

# io = process(["python3", "server.py"])
io = remote("tjc.tf", 31601)
io.recvuntil(b"<Bobby> i'll give you the powerful numbers, ")
c = Integer(io.recvuntil(b' and ', drop=True).decode())
n = Integer(io.recvuntil(b'\n', drop=True).decode())

io.recvuntil(b'<Bobby> btw do you want to get my diamond stash\n')
io.recvuntil(b'<You> ')
io.sendline(b'yea')
io.recvuntil(b"<Bobby> i'll send coords\n")
io.recvuntil(b"<Bobby> ")
l = Integer(io.recvuntil(b'\n', drop=True).decode())

for i in range(2**19 - 1, 2, -1):
    if (n - l + i ** 2) % i == 0:
        s = (n - l + i ** 2) // i
        x = var('x')
        result = solve(x**2 - s*x + n, x)
        result = str(result)
        if 'sqrt' not in result:
            result = eval(result)
            p = str(result[0])[5:]
            q = str(result[1])[5:]
            p = Integer(p)
            q = Integer(q)
            assert p * q == n
            d = inverse_mod(65537, (p - 1) * (q - 1))
            plain = pow(c, d, n)
            io.recvuntil(b'<You> ')
            io.sendline(str(plain).encode())
            io.interactive()