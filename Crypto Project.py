import string
from Crypto.Util.number import *
import binascii
from pwn import *
import base64

abt = string.printable
SV = [
    0xD76AA478,
    0xE8C7B756,
    0x242070DB,
    0xC1BDCEEE,
    0xF57C0FAF,
    0x4787C62A,
    0xA8304613,
    0xFD469501,
    0x698098D8,
    0x8B44F7AF,
    0xFFFF5BB1,
    0x895CD7BE,
    0x6B901122,
    0xFD987193,
    0xA679438E,
    0x49B40821,
    0xF61E2562,
    0xC040B340,
    0x265E5A51,
    0xE9B6C7AA,
    0xD62F105D,
    0x2441453,
    0xD8A1E681,
    0xE7D3FBC8,
    0x21E1CDE6,
    0xC33707D6,
    0xF4D50D87,
    0x455A14ED,
    0xA9E3E905,
    0xFCEFA3F8,
    0x676F02D9,
    0x8D2A4C8A,
    0xFFFA3942,
    0x8771F681,
    0x6D9D6122,
    0xFDE5380C,
    0xA4BEEA44,
    0x4BDECFA9,
    0xF6BB4B60,
    0xBEBFBC70,
    0x289B7EC6,
    0xEAA127FA,
    0xD4EF3085,
    0x4881D05,
    0xD9D4D039,
    0xE6DB99E5,
    0x1FA27CF8,
    0xC4AC5665,
    0xF4292244,
    0x432AFF97,
    0xAB9423A7,
    0xFC93A039,
    0x655B59C3,
    0x8F0CCC92,
    0xFFEFF47D,
    0x85845DD1,
    0x6FA87E4F,
    0xFE2CE6E0,
    0xA3014314,
    0x4E0811A1,
    0xF7537E82,
    0xBD3AF235,
    0x2AD7D2BB,
    0xEB86D391,
]


def leftCircularShift(k, bits):
    bits = bits % 32
    k = k % (2**32)
    upper = (k << bits) % (2**32)
    result = upper | (k >> (32 - (bits)))
    return result


def blockDivide(block, chunks):
    result = []
    size = len(block) // chunks
    for i in range(0, chunks):
        result.append(
            int.from_bytes(block[i * size : (i + 1) * size], byteorder="little")
        )
    return result


def F(X, Y, Z):
    return (X & Y) | ((~X) & Z)


def G(X, Y, Z):
    return (X & Z) | (Y & (~Z))


def H(X, Y, Z):
    return X ^ Y ^ Z


def I(X, Y, Z):
    return Y ^ (X | (~Z))


def FF(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + F(b, c, d) + M + t), s)
    return result


def GG(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + G(b, c, d) + M + t), s)
    return result


def HH(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + H(b, c, d) + M + t), s)
    return result


def II(a, b, c, d, M, s, t):
    result = b + leftCircularShift((a + I(b, c, d) + M + t), s)
    return result


def fmt8(num):
    bighex = "{0:08x}".format(num)
    binver = binascii.unhexlify(bighex)
    result = "{0:08x}".format(int.from_bytes(binver, byteorder="little"))
    return result


def bitlen(bitstring):
    return len(bitstring) * 8


def md5sum(msg):
    msgLen = bitlen(msg) % (2**64)
    msg = msg + b"\x80"
    zeroPad = (448 - (msgLen + 8) % 512) % 512
    zeroPad //= 8
    msg = msg + b"\x00" * zeroPad + msgLen.to_bytes(8, byteorder="little")
    msgLen = bitlen(msg)
    iterations = msgLen // 512

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    for i in range(0, iterations):
        a = A
        b = B
        c = C
        d = D
        block = msg[i * 64 : (i + 1) * 64]
        M = blockDivide(block, 16)

        a = FF(a, b, c, d, M[0], 7, SV[0])
        d = FF(d, a, b, c, M[1], 12, SV[1])
        c = FF(c, d, a, b, M[2], 17, SV[2])
        b = FF(b, c, d, a, M[3], 22, SV[3])
        a = FF(a, b, c, d, M[4], 7, SV[4])
        d = FF(d, a, b, c, M[5], 12, SV[5])
        c = FF(c, d, a, b, M[6], 17, SV[6])
        b = FF(b, c, d, a, M[7], 22, SV[7])
        a = FF(a, b, c, d, M[8], 7, SV[8])
        d = FF(d, a, b, c, M[9], 12, SV[9])
        c = FF(c, d, a, b, M[10], 17, SV[10])
        b = FF(b, c, d, a, M[11], 22, SV[11])
        a = FF(a, b, c, d, M[12], 7, SV[12])
        d = FF(d, a, b, c, M[13], 12, SV[13])
        c = FF(c, d, a, b, M[14], 17, SV[14])
        b = FF(b, c, d, a, M[15], 22, SV[15])
        a = GG(a, b, c, d, M[1], 5, SV[16])
        d = GG(d, a, b, c, M[6], 9, SV[17])
        c = GG(c, d, a, b, M[11], 14, SV[18])
        b = GG(b, c, d, a, M[0], 20, SV[19])
        a = GG(a, b, c, d, M[5], 5, SV[20])
        d = GG(d, a, b, c, M[10], 9, SV[21])
        c = GG(c, d, a, b, M[15], 14, SV[22])
        b = GG(b, c, d, a, M[4], 20, SV[23])
        a = GG(a, b, c, d, M[9], 5, SV[24])
        d = GG(d, a, b, c, M[14], 9, SV[25])
        c = GG(c, d, a, b, M[3], 14, SV[26])
        b = GG(b, c, d, a, M[8], 20, SV[27])
        a = GG(a, b, c, d, M[13], 5, SV[28])
        d = GG(d, a, b, c, M[2], 9, SV[29])
        c = GG(c, d, a, b, M[7], 14, SV[30])
        b = GG(b, c, d, a, M[12], 20, SV[31])
        a = HH(a, b, c, d, M[5], 4, SV[32])
        d = HH(d, a, b, c, M[8], 11, SV[33])
        c = HH(c, d, a, b, M[11], 16, SV[34])
        b = HH(b, c, d, a, M[14], 23, SV[35])
        a = HH(a, b, c, d, M[1], 4, SV[36])
        d = HH(d, a, b, c, M[4], 11, SV[37])
        c = HH(c, d, a, b, M[7], 16, SV[38])
        b = HH(b, c, d, a, M[10], 23, SV[39])
        a = HH(a, b, c, d, M[13], 4, SV[40])
        d = HH(d, a, b, c, M[0], 11, SV[41])
        c = HH(c, d, a, b, M[3], 16, SV[42])
        b = HH(b, c, d, a, M[6], 23, SV[43])
        a = HH(a, b, c, d, M[9], 4, SV[44])
        d = HH(d, a, b, c, M[12], 11, SV[45])
        c = HH(c, d, a, b, M[15], 16, SV[46])
        b = HH(b, c, d, a, M[2], 23, SV[47])
        a = II(a, b, c, d, M[0], 6, SV[48])
        d = II(d, a, b, c, M[7], 10, SV[49])
        c = II(c, d, a, b, M[14], 15, SV[50])
        b = II(b, c, d, a, M[5], 21, SV[51])
        a = II(a, b, c, d, M[12], 6, SV[52])
        d = II(d, a, b, c, M[3], 10, SV[53])
        c = II(c, d, a, b, M[10], 15, SV[54])
        b = II(b, c, d, a, M[1], 21, SV[55])
        a = II(a, b, c, d, M[8], 6, SV[56])
        d = II(d, a, b, c, M[15], 10, SV[57])
        c = II(c, d, a, b, M[6], 15, SV[58])
        b = II(b, c, d, a, M[13], 21, SV[59])
        a = II(a, b, c, d, M[4], 6, SV[60])
        d = II(d, a, b, c, M[11], 10, SV[61])
        c = II(c, d, a, b, M[2], 15, SV[62])
        b = II(b, c, d, a, M[9], 21, SV[63])
        A = (A + a) % (2**32)
        B = (B + b) % (2**32)
        C = (C + c) % (2**32)
        D = (D + d) % (2**32)
    result = fmt8(A) + fmt8(B) + fmt8(C) + fmt8(D)
    return result


def ceasar_encode(pt):
    key = int(input("Shift key: "))
    ct = ""
    for i in pt:
        ct += abt[(abt.index(i) + key) % len(abt)]

    return ct


def ceasar_decode(ct):
    key = int(input("Shift key: "))
    pt = ""
    for i in ct:
        pt += abt[(abt.index(i) - key) % len(abt)]
    return pt


def brute_force_ceasar(ct):
    res = []
    for key in range(len(abt) - 1):
        pt = ""
        for i in ct:
            pt += abt[(abt.index(i) + key) % len(abt)]
        res.append(pt)
    return res


def str_to_bin(pt):
    return "".join(format(ord(c), "08b") for c in pt)


def bin_to_str(ct):
    n = len(ct)
    pt = ""
    for i in range(0, n, 8):
        chunk = ct[i : i + 8]
        num = int(chunk, 2)
        pt += chr(num)
    return pt


def str_to_dec(pt):
    ct = ""
    for i in pt:
        ct += str(ord(i)) + " "
    return ct


def dec_to_str(ct):
    pt = ""
    ct = ct.split(" ")
    for i in ct:
        pt += chr(int(i))
    return pt


def bytes_to_str(pt):
    return bytes(pt, "utf-8")


def str_to_hex(ct):
    return str(bytes.fromhex(ct), "utf-8")


def hex_to_str(pt):
    pt = bytes_to_str(pt)
    return bytes.hex(pt)


def long_to_str(pt):
    return bytes_to_long(bytes_to_str(pt))


def str_to_long(ct):
    return str(long_to_bytes(ct), "utf-8")


def str_to_bytes(ct):
    return str(ct, "utf-8")


def xor_str(data1, data2):
    data1 = data1.encode()
    data2 = data2.encode()
    ct = xor(data1, data2)
    return ct


def encode_b64(data):
    sample_string = data
    sample_string_bytes = sample_string.encode("ascii")

    base64_bytes = base64.b64encode(sample_string_bytes)
    pt = base64_bytes.decode()

    return pt


def decode_b64(data):
    base64_string = data
    base64_bytes = base64_string.encode("ascii")

    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")
    return sample_string


def menu():
    print(
        """

                    0. Exit
                    1. Caesar
                    2. Dec <-> Bin
                    3. Ascii <-> Dec
                    4. Base64
                    5. Hash md5
                    6. Xor

        """
    )
    chon = int(input("Chon: "))
    return chon

    pass


def main():
    while True:
        chon = menu()
        if chon == 0:
            break
        elif chon == 1:
            print(
                """Select:
                    1. Encode
                    2. Decode
                    3. Brute Force
                """
            )
            chon2 = int(input("Select: "))
            if chon2 == 1:
                data = input("Input: ")
                res = ceasar_encode(data)
                print("Output: ", res)
            elif chon2 == 2:
                data = input("Input: ")
                res = ceasar_decode(data)
                print("Output: ", res)
            elif chon2 == 3:
                data = input("Input: ")
                res = []
                res = brute_force_ceasar(data)
                print("Output: ", res)
        elif chon == 2:
            print(
                """Select:
                    1. Str -> Bin
                    2. Bin -> Str
                """
            )
            chon2 = int(input("Select: "))
            if chon2 == 1:
                data = input("Input: ")
                res = str_to_bin(data)
                print("Output: ", res)
            elif chon2 == 2:
                data = input("Input: ")
                res = bin_to_str(data)
                print("Output: ", res)

        elif chon == 3:
            print(
                """Select:
                    1. Str -> Dec
                    2. Dec -> Str
                    
                """
            )
            chon2 = int(input("Select: "))
            if chon2 == 1:
                data = input("Input: ")
                res = str_to_dec(data)
                print("Output: ", res)
            elif chon2 == 2:
                data = input("Input: ")
                res = dec_to_str(data)
                print("Output: ", res)
        elif chon == 4:
            print(
                """Select:
                    1. Base64 encode
                    2. Base64 decode
                    
                """
            )
            chon2 = int(input("Select: "))
            if chon2 == 1:
                data = input("Input: ")
                res = encode_b64(data)
                print("Output: ", res)
            elif chon2 == 2:
                data = input("Input: ")
                res = decode_b64(data)
                print("Output: ", res)

        elif chon == 5:
            data = input("Input: ")

            res = md5sum(data.encode())
            print("Output: ", res)

        elif chon == 6:
            data1 = input("First input: ")
            data2 = input("Second input: ")
            res = xor(data1.encode(), data2.encode())
            print("Output: ", res)
            pass


if __name__ == "__main__":
    main()