#!/usr/bin/python3
import argparse
import rsa
from ECC import ECC
from Point import Point
import binascii
import time

def create_arguments():
    """Create command line argument for this program.
    """

    parser = argparse.ArgumentParser(
        description='Public Key based Cryptosystem'
    )
    parser.add_argument("mode", help="Mode used in this program, can be encrypt/decrypt/keygen.\
    If keygen is used and --")
    parser.add_argument("cipher", help="Cipher used in this program, can be RSA/ECC")
    parser.add_argument("-p", "--public_key", help="Public key file location")
    parser.add_argument("-l", "--key_length", help="Length of key")
    parser.add_argument("-v", "--private_key", help="Private key file location")
    parser.add_argument("-f", "--file", help="File input used in this program")
    parser.add_argument("-o", "--output", help="Output generated after encryption")

    return parser.parse_args()

def process_rsa(args):
    if (args.mode.lower() == "keygen"):
        filename_pub = args.public_key if args.public_key != None else "key.pub"
        filename_priv = args.private_key if args.private_key != None else "key.priv"
        key_length = int(args.key_length) if args.key_length != None else 32

        rsa.keygen(filename_pub, filename_priv, length = key_length)
    elif (args.mode.lower() == "encrypt") or (args.mode.lower() == "decrypt") :
        if args.file == None:
            raise Exception("No file input on " + args.mode + "ion process")
        if (args.mode.lower() == "encrypt") and args.public_key == None:
            raise Exception("No public key given on " + args.mode + "ion process")
        if (args.mode.lower() == "decrypt") and args.private_key == None:
            raise Exception("No private key given on " + args.mode + "ion process")
        output = args.output if args.output != None else "result.encrypted"

        data = open(args.file, 'rb').read()
        print("Plaintext:\n", data)

        if args.mode.lower() == "encrypt":
            key = rsa.RSAPublicKey(from_file = True, filename = args.public_key)
            enc = True
        else:
            key = rsa.RSAPrivateKey(from_file = True, filename = args.private_key)
            enc = False

        result = rsa.process(encrypt=enc, data=data, RSA_key=key)

        print("Ciphertext:\n", binascii.hexlify(result))
        print("Size:", len(result), 'bytes')
        with open(output, 'wb') as fout:
            fout.write(result)

    else:
        raise Exception("Unsupported Mode " + args.cipher)

def process_ecc(args):
    a, b, p = input("Insert a, b, and p variable for elliptic graph:\n").split()
    ecc = ECC(int(a), int(b), int(p))
    x, y = input("Insert base point G value:\n").split()
    ecc.set_g(Point(int(x),int(y)))
    k = input("Insert k value:\n")
    ecc.set_k(int(k))

    if (args.mode == "keygen"):
        filename_pub = args.public_key if args.public_key != None else "key.pub"
        n = input("Insert n value:\n")
        result = ecc.generate_pkey(int(n))
        open(filename_pub, 'wb').write(result)
        print("Public key: ", binascii.hexlify(result))


    elif (args.mode == "encrypt"):
        if args.file == None:
            raise Exception("No file input on " + args.mode + "ion process")
        if args.public_key == None:
            raise Exception("No public key given on " + args.mode + "ion process")
        output = args.output if args.output != None else "result.encrypted"

        data = open(args.file, 'rb').read()
        print("Plaintext:\n", data)

        result = ecc.encrypt_data(data, args.public_key)

        print("Ciphertext:\n", binascii.hexlify(result))
        with open(output, 'wb') as fout:
            fout.write(result)

    elif (args.mode == "decrypt"):
        if args.file == None:
            raise Exception("No file input on " + args.mode + "ion process")
        output = args.output if args.output != None else "result.encrypted"

        n = input("Insert n value\n")

        data = open(args.file, 'rb').read()
        print("Ciphertext:\n", binascii.hexlify(data))

        result = ecc.decrypt_data(data, int(n))

        print("Plaintext:\n", result)
        with open(output, 'wb') as fout:
            fout.write(result)

    else:
        raise Exception("Unsupported Mode " + args.cipher)

if __name__ == '__main__':

    args = create_arguments()

    start = time.time()
    if args.cipher.upper() == "RSA":
        process_rsa(args)
    elif args.cipher.upper() == "ECC":
        process_ecc(args)
    else:
        raise Exception("Unsupported Cipher " + args.cipher)
    end = time.time()
    print("Time Elapsed", end - start, 'second')
