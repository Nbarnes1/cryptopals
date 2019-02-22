from binascii import *

def fixedXOR(string1, string2):
    if(len(string1) == len(string2)):
        tmp1 = int(string1, 16)
        tmp2 = int(string2, 16)
        return hex(tmp1 ^ tmp2)
    else:
        print ("Error: Fixed XOR non-matching input size")
        return

def main(): 
    input1 = "1c0111001f010100061a024b53535009181c"
    input2 = "686974207468652062756c6c277320657965"

    result = fixedXOR(input1, input2)
    print (result)

if __name__ == "__main__":
    main()
