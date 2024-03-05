enc = '灩捯䍔䙻ㄶ形楴獟楮獴㌴摟潦弸弲㘶㠴挲ぽ'
flag = ''

for i in enc:
    first = ord(i) >> 8
    second = ord() % 2**8
    flag += chr(first) + chr(second)
print(flag)
