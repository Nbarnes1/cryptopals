import binascii
import base64
import M2Crypto

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

def main():
	key = "YELLOW SUBMARINE"
	
	ciphertext = open("challenge10.txt").read()
	ciphertext = base64.b64decode(ciphertext)

	test = decrypt(ciphertext, key, "aes_128_cbc")
	print test

if __name__ == '__main__':
	main()
