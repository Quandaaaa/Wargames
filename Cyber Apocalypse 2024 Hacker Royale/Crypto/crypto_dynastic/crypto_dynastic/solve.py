from random import randint

c = 'DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL'
p = ''
for i in range(len(c)):
    if not c[i].isalpha():
            p=p+c[i]
    else:
        for k in range(5):
            tmp = chr(ord(c[i]) + k*26 - i)
            if tmp.isalpha():
                p = p + tmp
                break

print(p)
