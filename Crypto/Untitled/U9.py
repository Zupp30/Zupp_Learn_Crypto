def gcd(a,b):
    return gcd(b,a%b) if b else a

print(gcd(66528, 52920))