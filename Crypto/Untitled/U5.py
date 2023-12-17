# flag = 'label'
# for i in flag:
#     num = ord(i) ^ 13
#     print(chr(num), end = '')

from pwn import *
flag = xor(b'label', 13)
print(flag)
