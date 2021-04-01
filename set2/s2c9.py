import binascii
import base64

BLOCKLEN = 20

def PKCS7(input):
	return input + chr(BLOCKLEN-len(input)%BLOCKLEN) * (BLOCKLEN-len(input)%BLOCKLEN)

def main():
	string1 = "YELLOW SUBMARINE"
	print string1
	print binascii.hexlify(PKCS7(string1))


if __name__ == '__main__':
	main()
