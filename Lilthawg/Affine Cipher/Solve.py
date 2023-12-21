import string
from Crypto.Util.number import inverse
 
table = string.printable[:-3]

a = 47
b = -50
a_inv = inverse(a, len(table))

f = lambda x : a_inv*(x - b) % len(table)

ct = '.^"^9{,, Z|c^ Wv|gc 5c_Lc|w_~cm)wWc+bZc+wQc+wcvbt6'

def decryption(ciphertext):
    pt = ''
    for char in ciphertext :
        i = table.index(char)
        c = table[f(i)]
        pt += c
    return pt
 
 
print(decryption(ct))


'''
.^"^
. is 75 from K is 46
^ is 87 from C is 38
" is 63 from S is 53

(46*a + b)% 97 == 75 --> 97*x + 75 == 46a + b
(38*a + b)% 97 == 87 --> 97*y + 87 == 38a + b 
(53*a + b)% 97 == 63 --> 97*z + 63 == 53a + b 

a = 47
b = -50
'''