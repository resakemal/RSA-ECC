#!/usr/bin/python3
import random
import math
import sys
import base64
import hashlib
from bitstring import BitArray
from pprint import pprint

class RSA():
    def __init__(self, key_length = 32):
        if key_length >= 57:
            print("Sorry if this program takes a long time generating your key...")
            print("Blame my bad random prime generator function :(")
        self.key_length = key_length

    def __is_prime(self, n):
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif (n % 2) == 0 or (n % 3) == 0:
            return False
        i = 5
        while (i * i) <= n:
            if (n % i) == 0 or (n % (i + 2)) == 0:
                return False
            i = i + 6
        return True

    # Generate random prime between 2 and 2 ^ n
    def __gen_prime(self):
        n = random.randint(2, 2 ** self.key_length)
        while not (self.__is_prime(n)):
            # print(n)
            n = random.randint(2, 2 ** self.key_length)
        return n

    # Extended euclidean algorithm
    def __xgcd(self, a,b):
        prev_x, x = 1, 0; prev_y, y = 0, 1
        while b:
            q = a // b
            x, prev_x = prev_x - q * x, x
            y, prev_y = prev_y - q * y, y
            a, b = b, a % b
        return a, prev_x, prev_y

    # Inverse modulo for a mod m
    def __inv_modulo(self, a, n):
        g, x, y = self.__xgcd(a, n)
        return x % n

    # Generate key dengan panjang kunci self.n bit
    def generate_key(self, limited=False):
        self.prime1 = self.__gen_prime()
        self.prime2 = self.__gen_prime()
        self.n = self.prime1 * self.prime2
        self.totient = (self.prime1 - 1) * (self.prime2 - 1)

        self.e = random.randint(1, (self.totient))
        while not (math.gcd(self.e, self.totient) == 1):
            if limited:
                # RNG ga sampe totient, cuma sampe 2 ** key_length
                # kalo engga ntar kegedean terus ga bisa ngehandle key gede :(
                self.e = random.randint(1, 2 ** (self.key_length))
            else:
                self.e = random.randint(1, (self.totient))
        self.d = self.__inv_modulo(self.e, self.totient)

        self.pub = RSAPublicKey(self.e, self.n)
        self.priv = RSAPrivateKey(self.e, self.d, self.n)
        return self.pub, self.priv

    # Plaintext is integer <= n
    def encrypt(self, plaintext):
        ciphertext = pow(plaintext, self.e, self.n)
        return ciphertext

    # Ciphertext is integer <= n
    def decrypt(self, ciphertext):
        plaintext = pow(ciphertext, self.d, self.n)
        return plaintext

    # set public key based on RSAPublicKey value
    def set_public_key(self, RSA_pub):
        if hasattr(self, 'e') and self.e != RSA_pub.e:
            raise Exception("Public Key Mismatch")

        self.e = RSA_pub.e
        self.n = RSA_pub.n

    # set private key based on RSAPrivateKey value
    def set_private_key(self, RSA_priv):
        if (hasattr(self, 'e') and self.e != RSA_priv.e) or \
           (hasattr(self, 'n') and self.n != RSA_priv.n):
            raise Exception("Public Key Mismatch")

        self.e = RSA_priv.e
        self.d = RSA_priv.d
        self.n = RSA_priv.n

class RSAPrivateKey():
    def __init__(self, e=0, d=0, n=0, from_file = False, filename = None):
        self.e = e
        self.d = d
        self.n = n

        if from_file and filename != None:
            content = open(filename, 'r').read().split("+")
            self.e = int(content[0], 16)
            self.d = int(content[1], 16)
            self.n = int(content[2], 16)

    def to_file(self, filename):
        content = hex(self.e) + "+" +\
                  hex(self.d) + "+" +\
                  hex(self.n)
        with open(filename, 'w') as fout:
            fout.write(content)

class RSAPublicKey():
    def __init__(self, e=0, n=0, from_file = False, filename = None):
        self.e = e
        self.n = n

        if from_file and filename != None:
            content = open(filename, 'r').read().split("+")
            self.e = int(content[0], 16)
            self.n = int(content[1], 16)

    def to_file(self, filename):
        content = hex(self.e) + "+" +\
                  hex(self.n)
        with open(filename, 'w') as fout:
            fout.write(content)

# Encrypt, plaintext must be a bytes/bytearray object
def process(data, RSA_key, encrypt = True):
    rsa = RSA()
    # print(data)
    if (encrypt):
        rsa.set_public_key(RSA_key)
        processed_data = data
    else:
        rsa.set_private_key(RSA_key)
        processed_data = data[1:]

    should_append = False

    # ubah data ke array of bit
    data_bit = ''
    for b in processed_data:
        data_bit += '{0:08b}'.format(b)
    # print('p',data_bit, len(data_bit))

    # split based on ukuran N -> convert ke bit, liat panjangnya
    if encrypt:
        load_size = len(bin(rsa.n)) - 3
        store_size = load_size + (8 - load_size % 8)
    else:
        store_size = len(bin(rsa.n)) - 3
        load_size = store_size + (8 - store_size % 8)
    # print (load_size, store_size)

    blocks = [data_bit[x:x+load_size] for x in range(0, \
              len(data_bit), load_size)]
    # print(blocks)
    if encrypt:
        if blocks[-1][0] == '0':
            flag = '11111111'
        else:
            flag = '00000000'
        print(flag)
    else:
        if data[0] == 255:
            should_append = True

    # ubah hasil split itu ke integer, terus tinggal rsa.encrypt
    for i in range(len(blocks)):
        # print('prev', int(blocks[i], 2))
        if encrypt:
            blocks[i] = rsa.encrypt(int(blocks[i], 2))
        else:
            blocks[i] = rsa.decrypt(int(blocks[i], 2))
        # print('aftr',blocks[i], type(blocks[i]))

        if not encrypt and i == len(blocks) - 1:
            blocks[i] = bin(blocks[i])[2:]
        else:
            template = '{0:0' + str(store_size) + 'b}'
            blocks[i] = template.format(blocks[i])

    # print(blocks)

    # balikin lagi ke bytes
    result_bit = ''.join(blocks)
    if encrypt:
        result_bit = flag + result_bit
    else:
        if should_append:
            # print('a')
            result_bit = ''.join(blocks[:-1])
            while (len(result_bit) + len(blocks[-1])) % 8 != 0:
                blocks[-1] = '0' + blocks[-1]
            result_bit += blocks[-1]

    # print('c:', result_bit, len(result_bit))

    # l = BitArray(bin=result_bit)
    #
    # result = l.bytes
    result = bytearray()
    for i in range(0, len(result_bit), 8):
        result.append(int(result_bit[i:i+8], 2))
    # print(result)
    return result

def md5(text):
    h = hashlib.md5()
    h.update(text)
    return h.hexdigest()

def keygen(filename_pub, filename_priv, length = 32):
    rsa = RSA(key_length=length)
    rsa.generate_key()
    rsa.priv.to_file(filename_priv)
    rsa.pub.to_file(filename_pub)

if __name__ == '__main__':

    #################################
    # Plaintext from file
    #################################
    plaintext = open('README.md', 'rb').read()
    print('plaintext', plaintext, 'len', len(plaintext))
    print('md5', md5(plaintext), '\n')

    pub = RSAPublicKey(from_file = True, filename = 'RSA/key.pub')
    priv = RSAPrivateKey(from_file = True, filename = 'RSA/key.priv')

    ciphertext = process(plaintext, pub, encrypt = True)
    # print('\nn',pub.n,priv.n,'\n')
    plaintext = process(ciphertext, priv, encrypt = False)

    print('plaintext', plaintext)
    print('md5', md5(plaintext))

    #################################
    # single block encrypt/decrypt
    #################################
    # rsa = RSA()
    # rsa.generate_key()
    # rsa.priv.to_file('RSA/key.priv')
    # rsa.pub.to_file('RSA/key.pub')
    # c = rsa.encrypt(2333)
    # print(rsa.decrypt(c))

    #################################
    # check key generation
    #################################
    # rsa = RSA()
    # rsa.generate_key()
    # rsa.priv.to_file('RSA/key.priv')
    # print(rsa.priv.e)
    # print(rsa.priv.d)
    # print(rsa.priv.n)
    #
    # priv2 = RSAPrivateKey(from_file = True, filename = 'RSA/key.priv')
    # print(priv2.e)
    # print(priv2.d)
    # print(priv2.n)
    #
    # print("--")
    # rsa.pub.to_file('RSA/key.pub')
    # print(rsa.pub.e)
    # print(rsa.pub.n)
    #
    # pub2 = RSAPublicKey(from_file = True, filename = 'RSA/key.pub')
    # print(pub2.e)
    # print(pub2.n)
