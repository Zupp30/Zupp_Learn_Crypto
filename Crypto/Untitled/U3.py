import base64

flag = '72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'
flag = base64.b64encode(bytes.fromhex(flag))
print(flag)

flag = bytes.hex(base64.b64decode(flag))
print(flag)