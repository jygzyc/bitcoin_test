import time
import random
import secrets
import hashlib
import json

class KeyGenerator:
    def __init__(self):
        self.POOL_SIZE = 256
        self.KEY_BYTES = 32
        self.CURVE_ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
        self.pool = [0] * self.POOL_SIZE
        self.pool_pointer = 0
        self.prng_state = None
        self.__init_pool()
        
    def seed_input(self, str_input):
        time_int = int(time.time())
        self.__seed_int(time_int)
        for char in str_input:
            char_code = ord(char)
            self.__seed_byte(char_code)
            
    def generate_key(self):
        big_int = self.__generate_big_int()
        big_int = big_int % (self.CURVE_ORDER - 1) # key < curve order
        big_int = big_int + 1 # key > 0
        key = hex(big_int)[2:]
        # Add leading zeros if the hex key is smaller than 64 chars
        key = key.zfill(self.KEY_BYTES * 2)
        return key

    def __init_pool(self):
        for i in range(self.POOL_SIZE):
            random_byte = secrets.randbits(8)
            self.__seed_byte(random_byte)
        time_int = int(time.time())
        self.__seed_int(time_int)

    def __seed_int(self, n):
        self.__seed_byte(n)
        self.__seed_byte(n >> 8)
        self.__seed_byte(n >> 16)
        self.__seed_byte(n >> 24)

    def __seed_byte(self, n):
        self.pool[self.pool_pointer] ^= n & 255
        self.pool_pointer += 1
        if self.pool_pointer >= self.POOL_SIZE:
            self.pool_pointer = 0
    
    def __generate_big_int(self):
        if self.prng_state is None:
            seed = int.from_bytes(self.pool, byteorder='big', signed=False)
            random.seed(seed)
            self.prng_state = random.getstate()
        random.setstate(self.prng_state)
        big_int = random.getrandbits(self.KEY_BYTES * 8)
        self.prng_state = random.getstate()
        return big_int

class BitcoinAddr:

    def __init__(self):
        self.a = int(
            '0x0000000000000000000000000000000000000000000000000000000000000000', 16)
        self.b = int(
            '0x0000000000000000000000000000000000000000000000000000000000000007', 16)
        self.Gx = int(
            '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 16)
        self.Gy = int(
            '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 16)
        self.G_point = (self.Gx, self.Gy)
        self.p = int(
            '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16)

    def __Mod_inv(self, a, n):
        lm, hm = 1, 0
        low, high = a % n, n
        while low > 1:
            ratio = high // low
            nm, new = hm - lm * ratio, high - low * ratio
            lm, low, hm, high = nm, new, lm, low
        return lm % n

    def __E_add(self, p, q):
        lam = ((q[1] - p[1]) * self.__Mod_inv(q[0] - p[0], self.p)) % self.p
        rx = (lam * lam - p[0] - q[0]) % self.p
        ry = (lam * (p[0] - rx) - p[1]) % self.p
        return rx, ry

    def __E_double(self, p):
        lam = ((3 * p[0] * p[0] + self.a) * self.__Mod_inv((2 * p[1]), self.p)) % self.p
        rx = (lam * lam - 2 * p[0]) % self.p
        ry = (lam * (p[0] - rx) - p[1]) % self.p
        return rx, ry

    def __Emultiply(self, point, secret_key):
        secret_key = int(secret_key, 16)
        secret_key = str(bin(secret_key))[2:]
        g = point
        for i in range(1, len(secret_key)):
            g = self.__E_double(g)
            if secret_key[i] == '1':
                g = self.__E_add(g, point)
        return g

    def __compress_Pub(self, point):
        if point[1] & 1:
            pub = '03' + hex(point[0])[2:]
        else:
            pub = '02' + hex(point[0])[2:]
        return pub
    
    def get_publicKey(self, secret_key):
        point = self.__Emultiply(self.G_point, secret_key)
        publicKey = self.__compress_Pub(point)
        return publicKey

    def get_address(self, key):
        pubk = self.__Emultiply(self.G_point, key)
        sa = self.__compress_Pub(pubk)
        tmpa = sha_256(sa)
        tmpa = rip_160(tmpa)
        tmpa_body = '00' + tmpa
        tmpa = tmpa_body
        tmpa = sha_256(tmpa)
        prefix = sha_256(tmpa)[:8]
        pro_address = tmpa_body + prefix
        return base58(pro_address)

def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    address_int = int(address_hex, 16)
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string


def sha_256(string):
    string = json.dumps(string).encode()
    string = hashlib.sha256(string).hexdigest()
    return string


def rip_160(string):
    string = json.dumps(string).encode()
    string = hashlib.new('ripemd160', string).hexdigest()
    return string


def test():
    key = KeyGenerator()
    key.seed_input('random')
    privateKey = key.generate_key()
    print(privateKey)

    bitcoin = BitcoinAddr()
    publicKey = bitcoin.get_publicKey(privateKey)
    address = bitcoin.get_address(privateKey)

    print(publicKey)
    print(address)


if __name__ == "__main__":
    test()
