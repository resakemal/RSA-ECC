#!/usr/bin/python3
import argparse
import rsa
import binascii

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
    if (args.mode == "keygen"):
        filename_pub = args.public_key if args.public_key != None else "key.pub"
        filename_priv = args.private_key if args.private_key != None else "key.priv"
        key_length = args.key_length if args.key_length != None else 32

        rsa.keygen(filename_pub, filename_priv, length = key_length)
    elif (args.mode == "encrypt") or (args.mode == "decrypt") :
        if args.file == None:
            raise Exception("No file input on " + args.mode + "ion process")
        if args.public_key == None:
            raise Exception("No public key given on " + args.mode + "ion process")
        output = args.output if args.output != None else "result.encrypted"

        data = open(args.file, 'rb').read()
        print("Plaintext:\n", data)

        key = rsa.RSAPublicKey(from_file = True, filename = args.public_key)
        result = rsa.process(encrypt=True, data=data, RSA_key=key)

        print("Ciphertext:\n", binascii.hexlify(result))
        with open(output, 'wb') as fout:
            fout.write(result)

    else:
        raise Exception("Unsupported Mode " + args.cipher)

if __name__ == '__main__':

    args = create_arguments()
    if args.cipher == "RSA":
        process_rsa(args)
    elif args.cipher == "ECC":
        pass
    else:
        raise Exception("Unsupported Cipher " + args.cipher)
