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


def main():
	ciphertext = open("challenge7.txt").read()
        ciphertext = base64.b64decode(ciphertext)
	ciphertext = binascii.hexlify(ciphertext)
	
	decrypted = decrypt(ciphertext, "YELLOW SUBMARINE", "aes_128_ecb")
	print decrypted


if __name__ == '__main__':
	main()
