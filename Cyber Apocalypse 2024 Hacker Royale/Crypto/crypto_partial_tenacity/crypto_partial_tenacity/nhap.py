from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# p = "151441473357136152985216980397525591305875094288738820699069271674022167902643"
# leak_p = ''
# for i in p:
#     leak_p += i + '?'
    
# q = "15624342005774166525024608067426557093567392652723175301615422384508274269305"
# leak_q = ''
# for i in q:
#     leak_q += '?' + i 
# print(leak_p)
# print(leak_q)

leak_p = "1?5?1?4?4?1?4?7?3?3?5?7?1?3?6?1?5?2?9?8?5?2?1?6?9?8?0?3?9?7?5?2?5?5?9?1?3?0?5?8?7?5?0?9?4?2?8?8?7?3?8?8?2?0?6?9?9?0?6?9?2?7?1?6?7?4?0?2?2?1?6?7?9?0?2?6?4?3"
leak_q = "?1?5?6?2?4?3?4?2?0?0?5?7?7?4?1?6?6?5?2?5?0?2?4?6?0?8?0?6?7?4?2?6?5?5?7?0?9?3?5?6?7?3?9?2?6?5?2?7?2?3?1?7?5?3?0?1?6?1?5?4?2?2?3?8?4?5?0?8?2?7?4?2?6?9?3?0?5?"
n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct = "7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476"
e = 65537
def guess(a, b, i, p, q):
    conditon = 1
    if b == '?':
        a, b = b, a
        p, q = q, p
        conditon = 0
    for _ in range(10):
        if str(int(str(_) + str(p)) * int(str(b) + str(q)))[-i:] == str(n)[-i:]:
            a = str(_)
            break
        
    if conditon:
        return a + p, b + q
    else:
        return b + q, a + p
    
p = ''
q = ''
index = 1
for i, j in zip(leak_p[::-1], leak_q[::-1]):
    p, q = guess(i, j, index, p, q)
    index += 1
    
p = int(p)
q = int(q)
assert p * q == n

phi = (p-1)*(q-1)
d = pow(e, -1, phi)

private_key = RSA.construct([n, e, d])

cipher = PKCS1_OAEP.new(private_key)
m = cipher.decrypt(bytes.fromhex(ct))
print(m)