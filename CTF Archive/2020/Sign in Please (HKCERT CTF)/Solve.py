# archive.cryptohack.org 1024
from pwn import *
from json import *

def send_request(hsh):
    return s.sendline(dumps(hsh).encode())

s = connect("archive.cryptohack.org", 1024)
print(s.recv())
