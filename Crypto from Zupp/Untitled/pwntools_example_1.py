# from pwn import * 
# import json

# HOST = "socket.cryptohack.org"
# PORT = 11112

# r = remote(HOST, PORT)


# def json_recv():
#     line = r.readline()
#     return json.loads(line.decode())

# def json_send(hsh):
#     request = json.dumps(hsh).encode()
#     r.sendline(request)


# print(r.readline())
# print(r.readline())
# print(r.readline())
# print(r.readline())

# request = {
#     "buy": "clothes"
# }
# json_send(request)

# response = json_recv()

# print(response)


import telnetlib
import json

HOST = "103.162.14.116"
PORT = 16002

tn = telnetlib.Telnet(HOST, PORT)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)


print(readline())
print(readline())
print(readline())
print(readline())


request = {
    "buy": "clothes"
}
json_send(request)

response = json_recv()

print(response)