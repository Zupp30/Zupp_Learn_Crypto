# p = 29
# ints = [14, 6, 11]

# qr = [a for a in range(p) if pow(a, 2, p) in ints]
# print(min(qr))

p = 29
ints = [14, 6, 11]
qr = 1e9

for a in range(p):
    if pow(a, 2, p) in ints:
        qr = min(a, qr)
print(qr)