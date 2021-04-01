import binascii
import base64
import M2Crypto
import os
from random import randint
import enum

BLOCKLEN = 16

def PKCS7(input):
        return input + chr(BLOCKLEN-len(input)%BLOCKLEN) * (BLOCKLEN-len(input)%BLOCKLEN)

def unPKCS7(input):
	if (len(input)%BLOCKLEN != 0): 
		raise Exception("Error: input must be multiple of block size")

	paddingChar = input[-1]
	paddingString = input[-ord(paddingChar):]
	
	if (ord(paddingChar) not in range(1,16)):
		raise Exception("Error: Invalid padding character")

	if not all(c == paddingChar for c in paddingString):
		raise Exception("Error: Invalid padding structure")

	return input[:-ord(input[-1])]	

def main():
	test = "Hello"
	print test
	padded = PKCS7(test)
	print binascii.hexlify(padded)
	unpadded = unPKCS7(padded)
	print binascii.hexlify(unpadded)
	print "-----"

	test = "YELLOW SUBMARIN\x05"
	unpadded = unPKCS7(test)

if __name__ == '__main__':
	main()
