from base64 import *
flag = 'SGV5ISBUaGlzIGlzIGFuIGV4YW1wbGUgb2YgYmFzZTY0IGVuY29kaW5nLg=='
flag = b64decode(flag)
print(flag)