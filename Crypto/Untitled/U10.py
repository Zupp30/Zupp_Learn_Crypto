r1, r2 = map(int, input().split())
s1, s2, t1, t2 = 1, 0, 0, 1
while r2:
    q, r = r1//r2, r1%r2
    s, t = s1 - q*s2, t1 - q*t2
    r1,r2, s1,s2, t1,t2 = r2,r, s2,s, t2,t
print(r1, s1, t1)
