

flag_enc = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
flag = ''

for i in range(0, len(flag_enc), 3):
    flag += flag_enc[i+2]
    flag += flag_enc[i]
    flag += flag_enc[i+1]
    
print(flag[::-1])
