tickets=[
(1,2,3,4,9,10),
(1,2,5,6,13,14),
(1,2,7,8,11,12),
(3,4,5,6,11,12),
(3,4,7,8,13,14),
(5,6,7,8,9,10),
(9,10,11,12,13,14)]

for i in range(1, 5):
    for j in range(7):
        tickets.append(tuple(_ + 14*i for _ in tickets[j]))
print(tickets)

from pwn import * 
io = remote("challenge.nahamcon.com",  30392)
io.recvuntil(b'>> ')
io.sendline(str(35).encode())

for i in tickets:
    for j in i:
        io.recvuntil(b'>> ')
        io.sendline(str(j).encode())
    
    
io.interactive()