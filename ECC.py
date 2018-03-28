from Point import Point
import array
import pickle
import binascii

class ECC:
    # Constructor
    def __init__(self):
        self.a = 0
        self.b = 0
        self.p = 0
        self.k = 0

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    # Setter
    def set_graph_var(self, _a, _b, _p):
        if self.__is_prime(_p):
            self.a = _a
            self.b = _b
            self.p = _p
        else:
            raise Exception(_p, " is not a prime")

    def set_k(self, _k):
        self.k = _k

    def set_g(self, _g):
        self.g = _g

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

    # Get first point on graph (smallest x)
    def get_points(self):
        x = 0
        y = 0
        for i in range(self.p):
            result = self.prime_mod_sqrt(pow(x,3) + self.a * x + self.b, self.p)
            if result:
                p1 = Point(x,result[0])
                p2 = Point(x,result[1])
                return [p1, p2]
            x += 1

    # Check if point is on graph
    def is_on_graph(self, pnt):
        return pow(pnt.Y, 2, self.p) == (pow(pnt.X,3) + self.a * pnt.X + self.b) % self.p

    # Define if a is a quadratic residue modulo of odd p
    def legendre_symbol(self, a, p):
        ls = pow(a, (p - 1) // 2, p)
        if ls == p - 1:
            return -1
        return ls

    # Return y where y^2 = n (mod p)
    def prime_mod_sqrt(self, a, p):
        a %= p

        # Simple case
        if a == 0:
            return [0]
        if p == 2:
            return [a]

        # Check solution existence on odd prime
        if self.legendre_symbol(a, p) != 1:
            return []

        # Simple case
        if p % 4 == 3:
            x = pow(a, (p + 1) // 4, p)
            return [x, p - x]

        # Factor p-1 on the form q * 2^s (with Q odd)
        q, s = p - 1, 0
        while q % 2 == 0:
            s += 1
            q //= 2

        # Select a z which is a quadratic non resudue modulo p
        z = 1
        while self.legendre_symbol(z, p) != -1:
            z += 1
        c = pow(z, q, p)

        # Search for a solution
        x = pow(a, (q + 1) // 2, p)
        t = pow(a, q, p)
        m = s
        while t != 1:
            # Find the lowest i such that t^(2^i) = 1
            i, e = 0, 2
            for i in range(1, m):
                if pow(t, e, p) == 1:
                    break
                e *= 2

            # Update next value to iterate
            b = pow(c, 2 ** (m - i - 1), p)
            x = (x * b) % p
            t = (t * b * b) % p
            c = (b * b) % p
            m = i

        return [x, p - x]

    # Point addition
    def add_points(self, p1, p2):
        grd = (p2.Y - p1.Y) * pow(p2.X - p1.X, self.p-2, self.p)
        _x = (pow(grd,2) - p1.X - p2.X) % self.p
        _y = (grd * (p1.X - _x) - p1.Y) % self.p
        return Point(_x, _y)

    # Point subtraction
    def sub_points(self, p1, p2):
        return self.add_points(p1, Point(p2.X, (-1 * p2.Y) % self.p))

    # Point duplication
    def duplicate_point(self, pnt):
        grd = (3 * pnt.X + self.a) * pow(2 * pnt.Y, self.p-2, self.p)
        _x = (pow(grd,2) - 2 * pnt.X) % self.p
        _y = (grd * (pnt.X - _x) - pnt.Y) % self.p
        return Point(_x, _y)

    # Point multiplication; nP = P + P + P ... n times
    def iterate_point(self, pnt, n):
        if n == 1:
            return pnt
        elif n % 2 == 0:
            return self.iterate_point(self.duplicate_point(pnt), n/2)
        elif n % 2 == 1:
            return self.add_points(self.iterate_point(self.duplicate_point(pnt), (n-1)/2), pnt)

    # Read plaintext file and return byte array
    def read_plain_file(self, filename):
        return open(filename, 'rb').read()

    # Write ciphertext to file
    def write_cipher_file(self, filename, data):
        fh = open(filename, 'wb')
        pickle.dump(data,fh)

    # Read ciphertext file and return byte array
    def read_cipher_file(self, filename):
        fh = open(filename, 'rb')
        return pickle.load(fh)

    # Write plaintext to file
    def write_plain_file(self, filename, data):
        open(filename, 'wb').write(data)

    # Convert byte value to point
    def plain_byte_to_point(self, m):
        x = m*self.k + 1
        for i in range(m*self.k + self.k - 1):
            check = self.prime_mod_sqrt(pow(x,3) + self.a * x + self.b, self.p)
            if (check != []):
                return Point(x, check[0])
            x += 1

    # Convert point to byte value
    def plain_point_to_byte(self, pnt):
        return (pnt.X - 1) // self.k

    # Generate public key based on point G and n value
    def gen_pkey(self, n):
        return self.iterate_point(self.g, n)

    # Encrypt plaintext point to 2 ciphertext points
    def encrypt(self, ptext, pkey):
        return [self.add_points(ptext, self.iterate_point(pkey, self.k)), self.iterate_point(self.g, self.k)]

    # Decrypt 2 ciphertext points into plaintext point
    def decrypt(self, p1, p2, nkey):
        return self.sub_points(p1, self.iterate_point(p2, nkey))

    def generate_pkey(self,n):
        return pickle.dumps(self.iterate_point(self.g, n))

    # Encrypt file
    def encrypt_data(self, data, pkey_file):
        # Read plaintext & public key
        p_key = pickle.loads(open(pkey_file, 'rb').read())

        # Convert plaintext to points
        point_array = []
        for i in data:
            point_array.append(self.plain_byte_to_point(i))

        # Encrypt point
        crypt_array = []
        for i in point_array:
            crypt_array.append(self.encrypt(i, p_key))

        return pickle.dumps(crypt_array)

    # Decrypt file
    def decrypt_data(self, data, n):
        data = pickle.loads(data)

        # Decrypt point
        point_array = []
        for i in data:
            point_array.append(self.decrypt(i[0], i[1], n))

        # Convert points to plaintext
        plain_array = bytearray()
        for i in point_array:
            plain_array.append(self.plain_point_to_byte(i))
        return plain_array

def test():
    # Initialize graph
    ecc = ECC(3, 5, 701)
    ecc.set_k(2)
    ecc.set_g(Point(0, 648))

    # Convert plaintext to points
    in_data = ecc.read_plain_file("plaintext/0.txt")
    p_point_array = []
    for i in in_data:
        p_point_array.append(ecc.plain_byte_to_point(i))

    # Define n and generate public key
    n = 11
    p_key = ecc.gen_pkey(n)
    print(binascii.hexlify(pickle.dumps(p_key)))

    # Encrypt point
    crypt_array = []
    for i in p_point_array:
        crypt_array.append(ecc.encrypt(i, p_key, ))

    # Write ciphertext
    ecc.write_cipher_file("test2.txt", crypt_array)
    print(binascii.hexlify(pickle.dumps(crypt_array)))

    # Read ciphertext
    c_data = ecc.read_cipher_file("test2.txt")

    # Decrypt point
    c_point_array = []
    for i in c_data:
        c_point_array.append(ecc.decrypt(i[0], i[1], n))

    # Convert points to plaintext
    out_data = bytearray()
    for i in c_point_array:
        val = ecc.plain_point_to_byte(i)
        if val > 255: val -= 255
        out_data.append(val)

    # Write plaintext to file
    ecc.write_plain_file("test3.txt", out_data)

if __name__ == '__main__':
    test()

