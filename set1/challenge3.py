from binascii import *
from challenge2 import fixedXOR

ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"



result = fixedXOR(ciphertext, "c"*len(ciphertext))

print (result)
print (result[2:])
print (bytes.fromhex(result[2:]))
print (b2a_uu(bytes.fromhex(result[2:])))
