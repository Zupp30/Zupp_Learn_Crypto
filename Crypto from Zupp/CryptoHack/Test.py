from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, inverse
import math
import random
from sympy import isprime


f = open('key.pem', 'rb').read()
key = RSA.importKey(f)
f = open('ciphertext.txt', 'r').read()

# n, e, ct = key.n, key.e, int('0x' + f, 16)
n = 4013610727845242593703438523892210066915884608065890652809524328518978287424865087812690502446831525755541263621651398962044653615723751218715649008058509
e = 65537
ct = 1917684880911867693650685352418976984109248146699653008498254042568729095851205293666079588834526955087298417903949404082481371089615961547716198943362344


primes = []
def sieve(maximum=10000):
    marked = [False]*(int(maximum/2)+1)
    for i in range(1, int((math.sqrt(maximum)-1)/2)+1):
        for j in range(((i*(i+1)) << 1), (int(maximum/2)+1), (2*i+1)):
            marked[j] = True
    primes.append(2)
    for i in range(1, int(maximum/2)):
        if (marked[i] == False):
            primes.append(2*i + 1)

def get_primorial(n):
    result = 1
    for i in range(n):
        result = result * primes[i]
    return result

def get_fast_prime():
    M = get_primorial(40)
    while True:
        k = random.randint(2**28, 2**29-1)
        a = random.randint(2**20, 2**62-1)
        p = k * M + pow(e, a, M)

        if isprime(p):
            return p

'''
p = k*M + (e^a)%M
M = 166589903787325219380851695350896256250980509594874862046961683989710
'''

sieve()
M = get_primorial(40)
a = random.randint(2**20, 2**62-1)
temp = pow(e, a, M)