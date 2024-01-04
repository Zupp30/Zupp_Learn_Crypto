# #       1234567890
# temp = '!@#$%^&*()'
# flag = '^&,*$,&),!@#,*#,!!^,(&,!!$,(%,$^,(%,*&,(&,!!$,!!%,(%,$^,(%,&),!!!,!!$,(%,$^,(%,&^,!)%,!)@,!)!,!@%'

# for i in temp:
#     flag = flag.replace(i, str((temp.index(i) + 1)%10))
#     flag = flag.replace("'", "")
#     flag = flag.replace(",", " ")

# flag = [chr(int(i)) for i in flag.split()]
# for i in flag: print(i, end = '')

'''
def decode_message(message, symbols, numbers):
    translation_table = str.maketrans(symbols, numbers)
    return message.translate(translation_table)

def numbers_to_ascii(numbers):
    return ''.join(chr(int(i)) for i in numbers.split(','))

symbols = "!@#$%^&*()"
numbers = "1234567890"
message = "^&,*$,&),!@#,*#,!!^,(&,!!$,(%,$^,(%,*&,(&,!!$,!!%,(%,$^,(%,&),!!!,!!$,(%,$^,(%,&^,!)%,!)@,!)!,!@%"

flag = decode_message(message, symbols, numbers)
print(numbers_to_ascii(flag))
'''

