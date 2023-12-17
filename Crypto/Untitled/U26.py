from Crypto.Util.number import *
#e = 1
#c = 9327565722767258308650643213344542404592011161659991421
n = 245841236512478852752909734912575581815967630033049838269083

e = 3
c = 219878849218803628752496734037301843801487889344508611639028
#m = pow(c, d, n)

p = 416064700201658306196320137931
q = 590872612825179551336102196593
f = (p-1)*(q-1)
d = inverse(e, f)
m = pow(c, d, n)

print(long_to_bytes(m))