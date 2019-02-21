from binascii import *

print ("test")

input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
encoded = b2a_base64(bytes.fromhex(input))

print (encoded)