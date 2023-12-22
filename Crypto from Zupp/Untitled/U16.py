a = [2, 3, 5]
m = [5, 11, 17]
n = [0, 0, 0]
y = [0, 0, 0]
N = 5*11*17
x = 0

#Calculate n[i] and y[i]:
for i in range(3): 
    n[i] = N//m[i]
    y[i] = pow(n[i], -1, m[i])
    x += a[i]*n[i]*y[i]
print(x%N)
