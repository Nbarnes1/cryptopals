import M2Crypto
import binascii
import base64

def newCipher(op, key, alg, iv=None):
        if iv == None:
                iv = '\0' * 16

        cipher = M2Crypto.EVP.Cipher(alg=alg, key=key, iv=iv, op=op)
        return cipher

def encrypt(plaintext, key, alg, iv=None):
        cipher = newCipher(1, key, alg, iv)
        output = cipher.update(plaintext)
        output += cipher.final()
        output = binascii.hexlify(output)
        return output

def decrypt(ciphertext, key, alg, iv=None):
        cipher = newCipher(0, key, alg, iv)
        ciphertext = binascii.unhexlify(ciphertext)
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

def main():
	ciphertextList = open("challenge8.txt").read().splitlines()
	repeatedBlocksPerLine = []

	for index, ciphertext in enumerate(ciphertextList):
		numRepeated = numRepeating16ByteBlocks(ciphertext)
		repeatedBlocksPerLine.append({'LineNum':index, 'numRepeated':numRepeated})

	for line in repeatedBlocksPerLine:
		if(line['numRepeated'] != 0):
			print line

if __name__ == '__main__':
	main()
