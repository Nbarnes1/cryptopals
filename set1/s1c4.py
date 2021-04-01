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

def main():
	challengeCiphers = open("challenge4.txt").read().splitlines()

	resultList = []

	for cipher in challengeCiphers:
		result = performXORBruteForce(cipher)
		if (result != 0):
			resultList.append(result)	



	resultList.sort(reverse=True, key=getScore)
	for result in resultList:
		print result	

if __name__ == '__main__':
	main()
