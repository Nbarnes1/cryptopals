import binascii
import base64

def fixedXOR(input1, input2):
        output = b"".join(chr(ord(a) ^ ord(b)) for a,b in zip(input1, input2))
        return output

def repeatedKeyXOR(input, key):
	repeatedKey = key * (len(input)/len(key) + 1)
	output = fixedXOR(input, repeatedKey)
	return output

def main():
	plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	
	print "Output of challenge repeated xor: ",
	print binascii.hexlify(repeatedKeyXOR(plaintext, key))
	


if __name__ == '__main__':
	main()

