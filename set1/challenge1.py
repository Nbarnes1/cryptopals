from binascii import *

def hexToB64(str):
    encoded = b2a_base64(unhexlify(str))
    return encoded[:-1]

def main():
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    result = hexToB64(input)
    print (result)


if __name__ == "__main__":
    main()



