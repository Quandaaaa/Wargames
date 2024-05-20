m = 2584844783
a = 779849675 
c = 23327 
x0 = 579927320
class Random():
    global m, a, c

    def __init__(self, x0):
        self.x0 = x0

    def random(self):
        self.x0 = (a*self.x0+c) % m
        return self.x0

encryptor = Random(x0)

flag_enc = open("out.txt", "r").readlines()[-1]
flag_enc = [int(i) for i in flag_enc.split()]
n = 987
for ind in range(len(flag_enc)):
    next = encryptor.random()
    if ind < 6:
        print(str(next))
    for __ in range(n-1):
        flag_enc[ind] ^= encryptor.random()

print(''.join([chr(i) for i in flag_enc]))
