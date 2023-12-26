import numpy as np

v1 = np.array([4, 1, 3, -1])
v2 = np.array([2, 1, -3, 4])
v3 = np.array([1, 0, -2, 7])
v4 = np.array([6, 2, 9, -5])

v = [v1, v2, v3, v4]
u = [None]*len(v)
u[0] = v[0]
for i in range(1, len(v)):
    u[i] = v[i]
    for j in range(i):
        t = (np.dot(u[j], v[i]))/(np.dot(u[j], u[j]))
        u[i] = u[i]- t*u[j]

print(round(float(u[3][1]), 5))