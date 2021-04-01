import binascii
import base64
import M2Crypto
import os
from random import randint

BLOCKLEN = 16

def PKCS7(input):
        return input + chr(BLOCKLEN-len(input)%BLOCKLEN) * (BLOCKLEN-len(input)%BLOCKLEN)

def newCipher(op, key, alg, iv=None):
        if iv == None:
                iv = '\0' * BLOCKLEN

        cipher = M2Crypto.EVP.Cipher(alg=alg, key=key, iv=iv, op=op)
        return cipher

def encrypt(plaintext, key, alg, iv=None):
	cipher = newCipher(1, key, alg, iv)
        output = cipher.update(plaintext)
        output += cipher.final()
        return output

def decrypt(ciphertext, key, alg, iv=None):
        cipher = newCipher(0, key, alg, iv)
        output = cipher.update(ciphertext)
        output += cipher.final()
        return output

def numRepeating16ByteBlocks(ciphertext):
	#Split into 16 byte blocks
	blocks = [ciphertext[x:x+16] for x in range(0,len(ciphertext),16)]
	
	seen = {}
	for block in blocks:
		print binascii.hexlify(block)
		if block not in seen:
			seen[block] = 0
		else:
			seen[block] += 1

	sum = 0
	for block in seen:
		sum += seen[block]
	return sum

#Create a random key, and prepend+append 5-10 bytes for obfuscation
def encryptionOracle(plaintext):
	randkey = os.urandom(16)
	prepend = os.urandom(randint(5,10))
	append = os.urandom(randint(5,10))

	newPlaintext = prepend + plaintext + append
	coinflip = randint(1,2)
	if (coinflip == 1):
		encrypted = encrypt(newPlaintext, randkey, "aes_128_ecb")
	elif (coinflip == 2):
		encrypted = encrypt(newPlaintext, randkey, "aes_128_cbc", os.urandom(16))

	return encrypted	

def detectMode(ciphertext):
	duplicatedBlocks = numRepeating16ByteBlocks(ciphertext)
	
	print "Number of duplicate blocks: " , duplicatedBlocks
	if (duplicatedBlocks > 0 ):
		print "Encrypted using ECB"
	else:
		print "Encrypted using CBC"
	
def main():
	key = "YELLOW SUBMARINE"
	
	plaintext = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"
	ciphertext = encryptionOracle(plaintext)
	#print "encrypted: " , binascii.hexlify(ciphertext), "\n"

	detectMode(ciphertext)
	

if __name__ == '__main__':
	main()
