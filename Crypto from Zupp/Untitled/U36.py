from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
from Crypto.Cipher import PKCS1_OAEP

f = open('key.pem', 'rb')
key = RSA.importKey(f.read())

ct = bytes.fromhex('249d72cd1d287b1a15a3881f2bff5788bc4bf62c789f2df44d88aae805b54c9a94b8944c0ba798f70062b66160fee312b98879f1dd5d17b33095feb3c5830d28')
p = 51894141255108267693828471848483688186015845988173648228318286999011443419469
q = 77342270837753916396402614215980760127245056504361515489809293852222206596161

fn = (p-1)*(q-1)
d = inverse(key.e, fn)

key = RSA.construct((key.n, key.e, d))
cipher = PKCS1_OAEP.new(key)
pt = cipher.decrypt(ct)

print(pt)
