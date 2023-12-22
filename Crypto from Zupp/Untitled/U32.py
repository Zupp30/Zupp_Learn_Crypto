from Crypto.PublicKey import RSA

"""
f = open('pem.pem', 'r')
a = RSA.importKey(f.read())
print(a.n)
"""

f = open('2048b-rsa-example-cert.der', 'rb')
a = RSA.importKey(f.read())

print(a.n)