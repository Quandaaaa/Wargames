from pwn import xor

# io = remote("treasury.squ1rrel-ctf-codelab.kctf.cloud", 1337)
# io.recvuntil(b'\n>')
# io.sendline(b'1')
# io.sendlineafter(b'> ',b'a'*14)

iv = bytes.fromhex('4a048459ad3ebc3b68c4c61d091a4b9b')
target = b'a:'+b'9'*14
c = bytes.fromhex("4ccffa2f796ce4381f37ba63a74d8a99")
new_iv = xor(xor(target, b'a'*14+b':0'), iv).hex()
print(new_iv)


