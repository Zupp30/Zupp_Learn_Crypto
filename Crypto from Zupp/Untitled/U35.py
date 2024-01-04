from Crypto.Util.number import inverse, long_to_bytes

n = 27772857409875257529415990911214211975844307184430241451899407838750503024323367895540981606586709985980003435082116995888017731426634845808624796292507989171497629109450825818587383112280639037484593490692935998202437639626747133650990603333094513531505209954273004473567193235535061942991750932725808679249964667090723480397916715320876867803719301313440005075056481203859010490836599717523664197112053206745235908610484907715210436413015546671034478367679465233737115549451849810421017181842615880836253875862101545582922437858358265964489786463923280312860843031914516061327752183283528015684588796400861331354873
e = 16
ct = 11303174761894431146735697569489134747234975144162172162401674567273034831391936916397234068346115459134602443963604063679379285919302225719050193590179240191429612072131629779948379821039610415099784351073443218911356328815458050694493726951231241096695626477586428880220528001269746547018741237131741255022371957489462380305100634600499204435763201371188769446054925748151987175656677342779043435047048130599123081581036362712208692748034620245590448762406543804069935873123161582756799517226666835316588896306926659321054276507714414876684738121421124177324568084533020088172040422767194971217814466953837590498718

# From: https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def tonelli(n, p):
    r = []
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p) #g
    r = pow(n, (q + 1) // 2, p) #x
    t = pow(n, q, p) #b
    m = s #r
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

# n is a prime number, so phi = n - 1
phi = n - 1
# d is not really the inverse because gcd(e, phi) = 8, but we have e * d = 8 mod phi
d = inverse(e//8, phi//8)
# In regular RSA, that would be the pt. But here since e * d = 8 mod phi, pt8 is pow(pt, 8, n)
pt8 = pow(ct, d, n)

# We know how to compute module square roots thanks to the tonelli algorithm
# Therefore we will search our solution by computing all the 8th root of pt8
def print_solutions(number, power):
  if power == 1:
    plaintext = long_to_bytes(number)
    if b"crypto" in plaintext:
      print(plaintext)
  else:
    r1 = tonelli(number, n)
    print_solutions(r1, power // 2)
    r2 = n - r1
    print_solutions(r2, power // 2)

print_solutions(pt8, 8)