# import base64
# from pwn import *

# flag = '73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d'

# flag = bytes.fromhex(flag)

# for i in range(1, 20):
#     k = xor(flag, i)
#     print(k)


input_str = bytes.fromhex('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')

key = input_str[0] ^ ord('c')
print(''.join(chr(c ^ key) for c in input_str))

#crypto{0x10_15_my_f4v0ur173_by7e}