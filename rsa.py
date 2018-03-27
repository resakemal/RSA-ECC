#!/usr/bin/python3
import random
import math
import sys
import base64
import hashlib

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
    def __init__(self, e=0, d=0, n=0):
        self.e = e
        self.d = d
        self.n = n

    def to_file(self, filename):
        content = hex(self.e) + "+" +\
                  hex(self.d) + "+" +\
                  hex(self.n)
        with open(filename, 'w') as fout:
            fout.write(content)

    def from_file(self, filename):
        content = open(filename, 'r').read().split("+")
        self.e = int(content[0], 16)
        self.d = int(content[1], 16)
        self.n = int(content[2], 16)

class RSAPublicKey():
    def __init__(self, e=0, n=0):
        self.e = e
        self.n = n

    def to_file(self, filename):
        content = hex(self.e) + "+" +\
                  hex(self.n)
        with open(filename, 'w') as fout:
            fout.write(content)

    def from_file(self, filename):
        content = open(filename, 'r').read().split("+")
        self.e = int(content[0], 16)
        self.n = int(content[1], 16)

# Encrypt, plaintext must be a bytes/bytearray object
def encrypt(plaintext, RSA_pub):
    rsa = RSA()
    rsa.set_public_key(RSA_pub)

    # ubah plaintext ke array of bit

    # split based on ukuran N -> convert ke bit, liat panjangnya

    # ubah hasil split itu ke integer, terus tinggal rsa.encrypt
    ciphertext = None
    return ciphertext

# Encrypt, ciphertext must be a bytes/bytearray object
def decrypt(ciphertext, RSA_priv):
    plaintext = bytes(0)
    return plaintext

def md5(text):
    h = hashlib.md5()
    h.update(text)
    return h.hexdigest()

if __name__ == '__main__':
    plaintext = open('plaintext/1.txt', 'rb').read()
    print(plaintext, md5(plaintext))

    rsa = RSA()
    pub, priv = rsa.generate_key()
    ciphertext = encrypt(plaintext, pub)
    plaintext = decrypt(ciphertext, priv)
    print(plaintext, md5(plaintext))

    #################################
    # single block encrypt/decrypt
    #################################
    # rsa = RSA()
    # rsa.generate_key()
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
    # priv2 = RSAPrivateKey()
    # priv2.from_file('RSA/key.priv')
    # print(priv2.e)
    # print(priv2.d)
    # print(priv2.n)
    #
    # print("--")
    # rsa.pub.to_file('RSA/key.pub')
    # print(rsa.pub.e)
    # print(rsa.pub.n)
    #
    # pub2 = RSAPublicKey()
    # pub2.from_file('RSA/key.pub')
    # print(pub2.e)
    # print(pub2.n)
