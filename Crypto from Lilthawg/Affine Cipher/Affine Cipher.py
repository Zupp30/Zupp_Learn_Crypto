#Affine Cipher extend
import string
import random
 
table = string.printable[:-3]
a = random.randint(1,len(table))
b = random.randint(0,len(table))
 
f = lambda x : (a*x + b) % len(table)
 
def encryption(plaintext):
    ciphertext = ''
    for char in plaintext :
        i = table.index(char)
        c = table[f(i)]
        ciphertext+=c
    return ciphertext
 
flag = 'KCSC{????????????????????????????????????????????}'
 
print(encryption(flag))
 
# '''
# ciphertext : .^"^9{,, Z|c^ Wv|gc 5c_Lc|w_~cm)wWc+bZc+wQc+wcvbt6
# '''
