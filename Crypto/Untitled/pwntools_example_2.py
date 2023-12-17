from pwn import * # pip install pwntools
from Crypto.Util.number import *
import json
import base64
import array
import codecs


r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

for i in range(0, 101):
    received = json_recv()

    if "flag" in received:
        print(received)
        break

    print("\n\n")
    print("Received type: ") 
    print(received["type"])
    print("Received encoded value: ") 
    print(received["encoded"])

    encoding = received["type"]
    word = received["encoded"]

    if encoding == "base64":
        decoded = base64.b64decode(word).decode('utf-8')
    elif encoding == 'hex':
        decoded_hex = codecs.getdecoder("hex_codec")
        decoded = decoded_hex(word)[0].decode('utf-8')
    elif encoding == 'rot13':
        decoded = codecs.encode(word, 'rot_13')
    elif encoding == 'bigint':
        decoded = long_to_bytes(int(word, 16)).decode('utf-8')
    elif encoding == "utf-8":
        decoded = array.array('b', word).tobytes().decode('utf-8')

    print("DECODED: "+decoded)

    to_send = {
        'decoded': decoded
    }

    json_send(to_send)

