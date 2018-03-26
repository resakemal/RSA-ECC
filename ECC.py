import Point

class ECC:
    # Constructor
    def __init__(self):
        self.a = 0
        self.b = 0
        self.p = 0

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    # Setter
    def set(self, _a, _b, _p):
        self.a = _a
        self.b = _b
        self.p = _p

    # Check if point is on graph
    def is_on_graph(self, pnt):
        return pow(pnt.Y,2) % self.p == (pow(pnt.X,3) + self.a * pnt.X + self.b) % self.p

    # Calculate y^2 = n (mod p)
    def tonelli_shanks(self, n, p):
        _p = p - 1
        q = 0
        s = 0
        while (q % 2 == 0):
            s += 1
            _s = pow(2,s)
            q = _p / _s

        i = 0
        z = 1
        while (z != p-1):
            i += 1
            z = pow(i,(p-1)/2) % p

        m = s
        c = pow(z,q)
        t = pow(n,q)
        r = pow(n,(q + 1)/2)

        i = 0
        b = 0
        while (i < m):
            if t == 0:
                return 0
            if t == 1:
                return r

            i = 0
            while (pow(t,pow(2,i)) != 1):
                i += 1

            b = pow(c,pow(2,m-i-1))
            c = pow(b,2)
            t *= pow(b,2)
            r *= b
        raise Exception('n is not a quadratic residue')

    # Point addition
    def add_points(self, p1, p2):
        grd = (p1.Y - p2.Y) / (p1.X - p1.Y)
        _x = (pow(grd,2) - p1.X - p2.X) % self.p
        _y = (grd * (p1.X - _x) - p1.Y) % self.p
        return Point(_x, _y)

    # Point subtraction
    def sub_points(self, p1, p2):
        return self.add_points(p1, Point(p2.X, (-1 * p2.Y) % self.p))

    # Point duplication
    def add_by_self(self, pnt):
        grd = (3 * pnt.X + self.a) * self.modinv(2 * pnt.Y, self.p)
        _x = (pow(grd,2) - 2 * pnt.X) % self.p
        _y = (grd * (pnt.X - _x) - pnt.Y) % self.p
        return Point(_x, _y)

    # Point multiplication; nP = P + P + P ... n times
    def n_add(self, pnt, n):
        base = pnt
        temp = Point()
        for i in range(n - 1):
            temp = self.add_by_self(base)
        return temp

    # Calculate inverse modulo
    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    # Calculate inverse modulo
    def modinv(self, a, m):
        g, x, y = self.egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m

    # Encrypt plaintext point to 2 ciphertext points
    def encrypt(self, g, ptext, pkey, k):
        return (self.n_add(g, k), self.add_points(ptext, self.n_add(pkey, k)))

    # Decrypt 2 ciphertext points into plaintext point
    def decrypt(self, p1, p2, nkey):
        return self.sub_points(p1, self.n_add(p2, nkey))