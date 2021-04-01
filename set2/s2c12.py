import binascii
import base64
import M2Crypto
import os
from random import randint
import enum

BLOCKLEN = 16

#EncryptionOracle object encrypts as follows: AES-128-ECB(your-string || append-string, key)
class EncryptionOracle:
	def __init__(self, key, append):
		self.key = key
		self.append = append

	def oracleEncrypt(self, plaintext):
		return encrypt(plaintext+self.append, self.key, "aes_128_ecb")
		
class CipherMode(enum.Enum):
	ECB = 1
	CBC = 2

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
		if block not in seen:
			seen[block] = 0
		else:
			seen[block] += 1

	sum = 0
	for block in seen:
		sum += seen[block]
	return sum

def detectMode(ciphertext):
	duplicatedBlocks = numRepeating16ByteBlocks(ciphertext)
	
	if (duplicatedBlocks > 0 ):
		return CipherMode.ECB
	else:
		return CipherMode.CBC

	return 0

def checkECB(oracle):
	plaintext = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"
	ciphertext = oracle.oracleEncrypt(plaintext)
	ciphermode = detectMode(ciphertext)
	
	if(ciphermode == CipherMode.ECB):
		return True
	else:
		return False
	
def findBlockSize(oracle):
	blocksize = -1	

	tmp = ""
	baseLen = len(oracle.oracleEncrypt(tmp))
	for i in range(1,256):
		tmp = "A" * i
		tmpLen = len(oracle.oracleEncrypt(tmp))
		if (baseLen != tmpLen):
			blocksize = tmpLen - baseLen
			return blocksize
	return blocksize

def crackSecret(oracle, blocksize):
	decrypted = ""
	secretLength = len(oracle.oracleEncrypt(""))
	lastBlockStart = secretLength-blocksize

	for byteIndex in range(secretLength-1,1,-1):
		fillerBytes = "A" * byteIndex
		ciphertext = oracle.oracleEncrypt(fillerBytes)
		
		for byteNum in range(0,256):
	                testCiphertext = oracle.oracleEncrypt(fillerBytes + decrypted + chr(byteNum))
        	        if (ciphertext[lastBlockStart:secretLength] == testCiphertext[lastBlockStart:secretLength]):
                	        decrypted += chr(byteNum)
         		        break
	return decrypted


def crackECB(oracle):
	blocksize = findBlockSize(oracle)

	if(checkECB(oracle)):
		return crackSecret(oracle, blocksize)


def main():	
	APPEND = open("challenge12.txt").read()
	APPEND = base64.b64decode(APPEND)	
	oracle = EncryptionOracle(os.urandom(16), APPEND)
	
	plaintext = "something"
	ciphertext = oracle.oracleEncrypt(plaintext)
#	print binascii.hexlify(ciphertext)

	secret = crackECB(oracle)
	print secret

if __name__ == '__main__':
	main()
