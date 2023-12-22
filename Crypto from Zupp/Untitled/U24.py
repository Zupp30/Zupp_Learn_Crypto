from pwn import xor
from Crypto.Random import get_random_bytes
from PIL import Image
from PIL import ImageDraw
"""
plaintext = 'abcd'

key = get_random_bytes(32)

img = Image.new('RGB', (800, 100))
drw = ImageDraw.Draw(img)
drw.text((20, 20), plaintext, fill=(255, 0, 0))
img.save("flag.png")
data = open("flag.png", 'rb').read()
encrypt_png = xor(data, key)

f = open('output', 'wb')
f.write(encrypt_png)

"""