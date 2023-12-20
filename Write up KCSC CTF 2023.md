# Write up KCSC CTF 2023
---

## 1. Ez_Ceasar (Easy)
---

### Mô tả: 
- Bài cung cấp flag đã được mã hóa bằng Caesar Cipher với bảng alphabet customed
- Challenge code: 
```
import string
import random

alphabet = string.ascii_letters + string.digits + "!{_}?"

flag = 'KCSC{s0m3_r3ad4ble_5tr1ng_like_7his}'
assert all(i in alphabet for i in flag)

key = random.randint(0, 2**256)

ct = ""
for i in flag:
    ct += (alphabet[(alphabet.index(i) + key) % len(alphabet)])

print(f"{ct=}")
# ct='ldtdMdEQ8F7NC8Nd1F88CSF1NF3TNdBB1O'
```

### Lời giải:
- Vì bài không sử dụng alphabet 26 chữ cái nên chúng ta sẽ in thử bảng alphabet customed với chỉ số tương ứng:

```
import string

alphabet = string.ascii_letters + string.digits + "!{_}?"
print(len(alphabet)) # len(alphabet) = 67
for i in range(68):
    print(i, alphabet[i], sep = ' is ')
```
nhận được
```
0 is a
1 is b
2 is c
3 is d
4 is e
5 is f
6 is g
7 is h
8 is i
9 is j
10 is k
11 is l
12 is m
13 is n
14 is o
15 is p
16 is q
17 is r
18 is s
19 is t
20 is u
21 is v
22 is w
23 is x
24 is y
25 is z
26 is A
27 is B
28 is C
29 is D
30 is E
31 is F
32 is G
33 is H
34 is I
35 is J
36 is K
37 is L
38 is M
39 is N
40 is O
41 is P
42 is Q
43 is R
44 is S
45 is T
46 is U
47 is V
48 is W
49 is X
50 is Y
51 is Z
52 is 0
53 is 1
54 is 2
55 is 3
56 is 4
57 is 5
58 is 6
59 is 7
60 is 8
61 is 9
62 is !
63 is {
64 is _
65 is }
66 is ?
```
- Sau khi nhận biết được từng chữ cái với chỉ số riêng, ta cần tìm được độ dịch chuyển (key) của bài. Mặc dù key là random nhưng ta có được format của cờ là 'KCSC{' nên có thể dễ dàng tìm được key dựa vào hai phương trình của chữ cái 'K' và 'C' đã được mã hóa thành 'l' và 'd'
```
(36[K] + key)%67 = 11[l]
(28[C] + key)%67 = 3[d]
```
- Dễ dàng tìm ra được valid key là 42, từ đó chúng ta giải mã:
```
ct = 'ldtdMdEQ8F7NC8Nd1F88CSF1NF3TNdBB1O'
pt = ''

for i in ct: pt += (alphabet[(alphabet.index(i) + 42) % 67])
print(pt)
```
> **Flag:**
> KCSC{C3as4r_1s_Cl4ss1c4l_4nd_C00l}
---

## 2. A3S_C1R (Easy)
---

### Mô tả:
- Bài cung cấp flag được mã hóa qua AES mode CTR
- Challenge code:
```
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

flag = b'KCSC{s0m3_r3ad4ble_5tr1ng_like_7his}'
nonce = Random.get_random_bytes(8)
countf = Counter.new(64, nonce)
key = Random.get_random_bytes(32)

encrypto = AES.new(key, AES.MODE_CTR, counter=countf)
encrypted = encrypto.encrypt(b"TODO:\n - ADD HARDER CHALLENGE IN CRYPTO\n - ADD FLAG TO THE CHALLENGE\n")

encrypto = AES.new(key, AES.MODE_CTR, counter=countf)
encrypted2 = encrypto.encrypt(flag)

print(f"encrypted: {encrypted.hex()}")
print(f"encrypted2: {encrypted2.hex()}")

# encrypted: 5e07dfa19e2b256c205df16b349c0863a15839d056ada1fb425449f2f9af9563eccca6d15cb01aabbe338c851f7b163982127033787fff49e74e3e09f0aee048a1d5b29f5a
# encrypted2: 410bc8addf6036125f5fe17d4bb61c00ba565a9e71d1bf846f625eeac5bfa972f9e7c4fd60800ac9aa689f9b280f5a09fd3768674401ac60
```

### Lời giải:
- Vì bài thuộc dạng AES với mode CTR, phương thức là XOR plaintext với các key. Tuy nhiên do cả hai đoạn encrypted và encrypted2 đều reuse encrypto, ta có:
    - xor(b"TODO:...", key) = encrypted
    - xor(flag, key) = encrypted2
- Dựa vào tính chất của phép xor, ta dễ dàng recover flag bằng cách xor encrypted, encrypted2, flag với nhau
```
A^B = B^A
A^(B^C) = (A^B)^C
A^0 = A
A^A = 0
```
- Code:
```
from pwn import xor

encrypted1 = '5e07dfa19e2b256c205df16b349c0863a15839d056ada1fb425449f2f9af9563eccca6d15cb01aabbe338c851f7b163982127033787fff49e74e3e09f0aee048a1d5b29f5a'
encrypted2 = '410bc8addf6036125f5fe17d4bb61c00ba565a9e71d1bf846f625eeac5bfa972f9e7c4fd60800ac9aa689f9b280f5a09fd3768674401ac60'
tmp = b"TODO:\n - ADD HARDER CHALLENGE IN CRYPTO\n - ADD FLAG TO THE CHALLENGE\n"

e1, e2 = bytes.fromhex(encrypted1),  bytes.fromhex(encrypted2)
print(xor(e1, e2, tmp))
```
nhận được:
```
b'KCSC{A3S_CTR_bU1_K1nd4_3asY_y0u_5h0uld_h4v3_s0lv3d_th1s}\xee\x00\xd6\xe7g\x8f\x9a\x16\xbb\xc4\x14\xa7\x1b'
```
> **Flag:**
> KCSC{A3S_CTR_bU1_K1nd4_3asY_y0u_5h0uld_h4v3_s0lv3d_th1s}
---

## 3. Is_it_CRT (Easy)
---

### Mô tả:
- Bài cho hint về CRT(vô nghĩa) và RSA(cho e - pub.expo) để giải flag 
- Challenge text:
```
e = 65537
n1 = 130970791706695167120816954281347910242271741380848697030582097380414164464669582077501935100534315672736591163867589462360532537474343007717114862677036219839049659638193590918904482709879798794387701429067711189339541090962315499562919351155480834958649104605830303759610881412035697138279914413112238740763
n2 = 113641455496435721193134074028475386176456392079379291332104843107150260592574545964197594045447402797691233409140148854647138554130435281685396694982224051757694663968334285795059648876331981127831706285859528658283228869511829743448319293252496057080243050538084390601445944010478822202867577802474801791329
n3 = 115457592377723871442877828120043009812666552225344030925643785294781982752845765738712585283013530383946783306354281324295808919863405271857497036597560796067884303380890822753721631162428079111639955037289448237030785776123607750456878915823785099809072723104652279115157324089611136858768836165863398680203
c1 = 30205641158783357163061598073735588730679950235840534382941497051587980282400902972347912576505274818761099007699493094299366801627409654097234796805851040864489706974546874446811476122681874102134051059499515262761274274546668369933320015216502163383548510236101225370599258753560708068722034210162626804923
c2 = 7340742323302407330422449647684226850070712253152501455033801379382023949033438352721378237409230914162113993246249149771113074063922424514756305027050874444877721126264284642454264098887344586634403180691682203341368972229942120849177826057673408055065848316876227141406653440730644459969340909926030700535
c3 = 55645356229576991726290820253166125559920178689701167851283019943562627606690176220109383257847017836775793827103662981412236830329482802454580242635314923411008056558210411063545158619407523528841487658337051518783958350562281456553772083003206890498586599056920249966475452673566793925144997181076187273153

```
### Lời giải:
- Nhận thấy bài cho e (hint về RSA) và cho 3 cặp số (n, c), tuy nhiên flag là duy nhất nên chúng ta chỉ cần giải flag với một cặp (n, c)
- Somehow n1 không thể factor sử dụng factor.db, bên cạnh đó ta nhận thấy gcd(n1, n2) != 1 nên n1, n2 không là các số nguyên tố cùng nhau, điều đó chứng minh n1 có thể factor được bằng cách sử dụng gcd(n1, n2); từ đó ta tìm được ước nguyên tố p, q của n1
```
from numpy import gcd

p, q = gcd(n1, n2), n1//gcd(n1, n2)
```
nhận được
```
p = 11353881877324711003979802139615058395337484069869327204614462296439884334893855149363852440127790628732414633471088851321186317538207960792596592119477097
q = 11535331538745540714738141702022923616940235271330067953307665528444215968500323164146763365026710855489137432279572472935140454733482859072047176027793379
```
đối với một bài RSA, tìm ra được p và q giúp ta dễ dàng giải mã flag:
```
from Crypto.Util.number import long_to_bytes, inverse

fn = (p-1)*(q-1) #phi hàm euler
d = inverse(e, fn) #private key
pt = pow(c1, d, n1)
print(long_to_bytes(pt))
```
> **Flag:**
> KCSC{N0t_Rea11y_4_CR1_4tt4ck_R1ght??!!??}

### NOTE:
- Note 1: Chúng ta không nhất thiết phải tìm ra hai số p và q, chỉ cần một số p đã có thể giải quyết bài toán
- Note 2: Phi hàm euler của p (fp) được sử dụng để đếm số các số nguyên tố cùng nhau với p, tuy nhiên trong bài, p là số nguyên tố nên fp = p-1
- Note 3: Đối với Multiparty RSA (MR) như bài này, điều kiện cần của bài là n1, n2, n3 phải đôi một là hai số nguyên tố cùng nhau. Tuy nhiên đề bài không thỏa mãn nên ta có thể rút gọn các số n1, n2, n3 về gcd(n1, n2) , gcd(n2, n3), gcd(n3, n1)
- Dựa vào các note 1, 2, 3 ta có thể rút gọn công đoạn tính toán và tìm ra flag:
```
f = gcd(n1, n2)-1
pt = pow(c1, inverse(e, f), gcd(n1, n2))
print(long_to_bytes(pt))
```
---

## 4. Ceasar_but_Harder!!!! (Medium)
---

### Mô tả:
- Bài cung cấp flag đã được mã hóa bằng Caesar Cipher với bảng alphabet customed (64 kí tự sau khi mất đi 3 kí tự bất kì)
- Challenge code:
```
import string
import random

flag = "KCSC{s0m3_r3ad4ble_5tr1ng_like_7his}" 

alphabet = string.ascii_letters + string.digits + "!{_}?"
assert all(i in alphabet for i in flag)


for i in range(3):
    k = random.randint(0, len(alphabet))
    alphabet = alphabet[:k] + alphabet[k+1:]

key = random.randint(0, 2**512)

ct = ""
for i in flag:
    ct += (alphabet[(alphabet.index(i) + key) % len(alphabet)])

print(f"{ct=}")

# ct='2V9VnRcNosvgMo4RoVfThg8osNjo0G}mmqmp'
```

### Lời giải:
- Là bài khó hơn Ez_Ceasar nhưng vẫn dựa trên ý tưởng cũ, ta có được chỉ số trên bảng chữ cái raw (67 kí tự) tương ứng với known text là KCSC{}
- KCSC{} ---> 2V9Vnp
- Như vậy:
    - C(28) ---> V(47) ~ +19
    - K(36) ---> 2(54) ~ +18
    - S(44) ---> 9(61) ~ +17
    - {(63) ---> n(13) ~ -50 ~ +17
    - }(65) ---> p(15) ~ -50 ~ +17
- Nhận thấy bảng chữ cái bị khuyết đi ba kí tự bất kì nên độ dịch chuyển (k) bị giảm đi đúng 3 đơn vị, dễ dàng dự đoán:
    - Chữ cái bị mất đầu tiên nằm trong (0, 28) | k = +20 ---> +19
    - Chữ cái bị mất thứ ba nằm trong (36, 44) | k = +19 ---> +18
- Do vậy, tất cả các chữ cái từ [44, 66] đều dịch chuyển +17 hay -50
- Dựa vào đó, code:
```
import string

alphabet = string.ascii_letters + string.digits + "!{_}?"
for i in range(44, 67): 
    print(i, 'from', alphabet[i%67], 'to', alphabet[(i+17)%67])
```
cho ra output:
```
44 from S to 9
45 from T to !
46 from U to {
47 from V to _
48 from W to }
49 from X to ?
50 from Y to a
51 from Z to b
52 from 0 to c
53 from 1 to d
54 from 2 to e
55 from 3 to f
56 from 4 to g
57 from 5 to h
58 from 6 to i
59 from 7 to j
60 from 8 to k
61 from 9 to l
62 from ! to m
63 from { to n
64 from _ to o
65 from } to p
66 from ? to q
```
giúp ta thay thế được các kí tự có trong flag đã mã hóa, từ đó làm tương tự với hai khoảng (0,28) và (28, 36), thử các số ở hai cận kết hợp phán đoán các từ có trong flag, ta giải mã được cờ

> **Flag:**
> KCSC{y0u_be4t_My_C3A54R_bu7_HoW!!?!}


## 5. Basic Math (Medium)
---

### Mô tả:
- Bài cung cấp flag sẽ được revealed sau 20 lần nhập đúng giá trị của x và h sao cho thỏa mãn phương trình
- Challenge code:
```
from Crypto.Util.number import getPrime

flag = b'KCSC{fake_flag}'

def verify(g, p, y, x, k, h):
    return (y*x*pow(g, k, p)) % p == pow(g, h, p)

p = getPrime(256)
g = getPrime(128)
y = 65537

lst_x = []
lst_h = []

print(f"p = {p}")
print(f"g = {g}")
print(f"y = {y}")

try:
    for i in range(20):
        x = 0
        h = 0
        x = int(input("x = "))
        h = int(input("h = "))
        if x in lst_x or h in lst_h:
            print('get out !!!')
            exit(-1)
        rs = verify(g, p, y, x, i, h)
        if rs:
            lst_x.append(x)
            lst_h.append(h)
        else:
            print('get out !!!')
            exit(-1)
            
    flag = open('flag.txt', 'rb').read()
    print(flag)
except:
    print("something went wrong")
```

### Lời giải:
- Đối với bài, điều quan trọng là phải tìm được giá trị của x và h thỏa mãn. Bên cạnh đó, với phép toán mô-đun, một bài toán sẽ có rất nhiều kết quả (có nhiều x với mỗi h tương ứng). Vì vậy, ta cần phải tìm được liên hệ giữa x và h, qua đó giải và nhận cờ.
- Tuy nhiên, biến số i được thay đổi += 1 sau mỗi lần nhập kết quả chính xác; và hai giá trị (x, h) không được nhập lại nên cần phải lưu ý.
- Mở đầu bài toán, chúng ta cần giải phương trình: ```(y*x*pow(g, k, p)) % p == pow(g, h, p)```
- Từ đây ta có các phép biến đổi:
```
            x * y * (pow(g, k, p)) ≡ g**h   (mod p)
such that   x * pow(g, k, p) ≡ inverse(y, p) * (g**h)   (mod p) [Ta chuyển y sang VP được vì y và p là coprime]
such that   x * (g**k) ≡ inverse(y, p) * (g**h)   (mod p) [Có thể dùng assert để kiểm chứng biến đổi từ dòng trên xuống dòng dưới]
such that   x ≡ inverse(y, p) * (g**(h-k))   (mod p)
- Đến được bước này, ta đã hoàn thành công việc tìm mối liên hệ giữa x và h, vì là phép mô-đun nên ta có thể chọn x tùy ý; ở đây chọn x = inverse(y, p)*pow(g, h-k) + p
- Tuy nhiên ta cần phải thay đổi hiệu h-k để (x, h) khác nhau qua mỗi lần nhập, vì vậy gọi delta = h-k, ta có code:
```
```
from Crypto.Util.number import inverse

#p = 
#g = 
#y = 


delta = 0
for i in range(20):
    x = inverse(y, p)*pow(g, delta) + p
    print(x, delta+i, end = '\n\n\n')
    #assert (x*y*pow(g, i, p))%p == pow(g, delta+i, p)
    delta += 1
```
- Kết nối với ```nc 103.162.14.116 16002```, ta nhận giá trị của p, g, y, thay vào code và nhận output, nhập các đáp án lần lượt và flag sẽ được trả về:
```b'KCSC{b4by_m4th_f0r_b4by_crypt0}'```

> **Flag:**
> KCSC{b4by_m4th_f0r_b4by_crypt0}
---