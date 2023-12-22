from Crypto.Util.number import *
c = 62324783949134119159408816513334912534343517300880137691662780895409992760262021
n = 1280678415822214057864524798453297819181910621573945477544758171055968245116423923
e = 65537

#We have to first find out the value of p and q such that n = p*q
#Using factor.db for n we get:
p = 1899107986527483535344517113948531328331
q = 674357869540600933870145899564746495319033

#Then we have to find f = f(n) = LCM(p-1, q-1):
f = (p-1)*(q-1)

#Then we have d = pow(e, -1, f)
d = pow(e, -1, f)

#Decipher text is pow(c, d, n)
flag = pow(c, d, n)

print(long_to_bytes(flag))