import binascii
import base64

CHARACTER_FREQ = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

def fixedXOR(input1, input2):
        output = b"".join(chr(ord(a) ^ ord(b)) for a,b in zip(input1, input2))
        return output

def repeatedKeyXOR(input, key):
        repeatedKey = key * (len(input)/len(key) + 1)
        output = fixedXOR(input, repeatedKey)
        return output

def performXOR(inputHex, keyVal):
        inputBytes = binascii.unhexlify(inputHex)
	outputBytes = ""
	
	for byte in inputBytes:
		outputBytes += chr(ord(byte) ^ ord(keyVal))	

	return outputBytes

def performXORBruteForce(cipherHex):
	resultList = []

        for i in range(256):
                result = performXOR(cipherHex, chr(i))
                score = round(basicEnglishScore(result), 4)
                resultEntry = {'result':result, 'score':score, 'keyVal': chr(i)}

                if (isAscii(result)):
                        resultList.append(resultEntry)

        resultList.sort(reverse=True, key=getScore)
	if (len(resultList) == 0 ):
		return 0
	return resultList[0]	



def basicEnglishScore(inputString):
	score = 0;

	for byte in inputString:
		score += CHARACTER_FREQ.get(byte.lower(), 0)

	return score;

def isAscii(s):
	return all((ord(c) < 128 and ord(c) > 31 or ord(c) == 10) for c in s)

def getScore(element):
	return element['score']

def getEditDistance(element):
	return element['editDistance']

def binify(inputString):
	return bin(int(binascii.hexlify(inputString),16))

def hammingDistance(input1, input2):
	return sum(a != b for a,b in zip(input1, input2))

#Splits ciphertext into chunks of 2i length. Computes Hamming distance between [:i] and [i:2i] for each chunk.
#Returns average edit distance normalized by dividing by i (keysize)
def avgHammingDistance(ciphertext, i):
	
	chunkLen = 2*i
	chunks = len(ciphertext)/chunkLen
	sumEditDistance = 0;

	for chunkNum in range(chunks):
		section1 = ciphertext[chunkNum*chunkLen:chunkNum*chunkLen + i]
		section2 = ciphertext[chunkNum*chunkLen + i:chunkNum*chunkLen + (2*i)]
		editDistance = hammingDistance(binify(section1), binify(section2))
		sumEditDistance += editDistance
	
	return round(((sumEditDistance*1.0)/chunks)/i,4)

#Given ciphertext, computes most likely keysize and attempts to crack the key. 
def repeatedKeyXORBruteForce(ciphertext):
	editDistances = []	
	crackedKey = ""

	#For each possible keysize, find average Hamming Distance
	for i in range(3,40):
		editDistance = avgHammingDistance(ciphertext, i)
		editDistances.append({'keyVal':i, 'editDistance':editDistance})
	
	editDistances.sort(key=getEditDistance)
	
	for block in editDistances[:5]:		#5 most likely key sizes
		possibleKey = repeatedKeyXOR_crackKey(ciphertext, block['keyVal'])
		print block	#print keySize and hamming score
		if (possibleKey != ""):
			print "[+] Discovered key: <" , possibleKey , ">"
			crackedKey = possibleKey
	return crackedKey

#Given ciphertext and keysize, return the most likely repeated key used for encryption
def repeatedKeyXOR_crackKey(ciphertext, keySize):
	ciphertextBlocks = []
	crackedKey = ""

	for blockIndex in range (keySize):
		newBlock = ciphertext[blockIndex::keySize]	#Take every i'th char corresponding to XOR key
		ciphertextBlocks.append(newBlock)

	#XOR crack each block individually
	for block in ciphertextBlocks:
		result = performXORBruteForce(binascii.hexlify(block))
		if(result != 0):
			crackedKey += result["keyVal"]
			
	return crackedKey

def main():
	ciphertext = open("challenge6.txt").read()
	ciphertext = base64.b64decode(ciphertext)	
	crackedKey = repeatedKeyXORBruteForce(ciphertext)
	
	print "Do you want to see the decrypted text? (y/n) "
	input = raw_input()
	if(input == 'y'):
		output = repeatedKeyXOR(ciphertext, crackedKey)
		print output


if __name__ == '__main__':
	main()
