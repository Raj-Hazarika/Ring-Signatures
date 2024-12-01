import hashlib
import random
from functools import reduce


class RingSignature:
    def __init__(self, keys, L=1024):
        self.keys = keys  # list of (public_key, private_key, n) tuples
        self.L = L  # bit length
        self.n = len(keys)  # number of participants
        self.q = 1 << (L - 1)  # large prime-like number

    def sign(self, message, signer_index):
        self._permut(message)  # computes the hash of the message
        s = [None] * self.n  # initializes a list with the length as the number of members in the group
        u = random.randint(0, self.q)  # generate random initial value
        c = v = self._E(u)  # compute the encryption of the random value with the message hash as key
        for i in (list(range(signer_index + 1, self.n)) + list(range(signer_index))):
            #  the loop go over all the keys except the actual signer
            s[i] = random.randint(0, self.q)
            e = self._g(s[i], self.keys[i][0], self.keys[i][2])
            v = self._E(v ^ e)
            if (i + 1) % self.n == 0:
                c = v   # make sure the final value is equal to the initial value

        s[signer_index] = self._g(v ^ u, self.keys[signer_index][1], self.keys[signer_index][2])  # actual signer signs to balance the ring signature equation
        return [c] + s

    def verify(self, message, signature):
        self._permut(message)  # computes the hash of the message

        def _f(i):
            return self._g(signature[i + 1], self.keys[i][0], self.keys[i][2])  # use naive RSA for verifying, the ring signature is used

        y = list(map(_f, list(range(len(signature) - 1))))

        def _g(x, i):
            return self._E(x ^ y[i])  # computes XOR

        r = reduce(_g, list(range(self.n)), signature[0])
        return r == signature[0]

    def _permut(self, message):
        self.p = int(hashlib.sha1(message.encode()).hexdigest(), 16)  # compute hash

    def _E(self, x):
        msg = f'{x}{self.p}'
        return int(hashlib.sha1(msg.encode()).hexdigest(), 16)  # encrypt using the message hash as the key

    def _g(self, x, e, n):
        return pow(x, e, n)  # naive RSA implementation - x**e mod n


def is_prime(n, k=5):  # number of tests
    """
    Test if a number is prime, prime numbers are required for naive RSA
    The code is taken from https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < r and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime_candidate(length):
    """
    Generate an odd integer randomly.
    Not using even integer as all even are composite except for 2.
    """
    p = random.getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p


def generate_prime_number(length=1024):
    """ Generate a prime """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


# Helper function to generate RSA-like keys for simplicity - Naive RSA as explained in class
def generate_keys(size=1024):
    p = generate_prime_number(size // 2)
    q = generate_prime_number(size // 2)
    n = p * q
    e = 65537  # commonly used public exponent
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return (e, d, n)


# Example usage
size = 4
message = "Hello CMPUT 496"
keys = [generate_keys() for _ in range(size)]

print(f"Message: {message}")
r = RingSignature(keys)

for i in range(size):
    signature = r.sign(message, i)
    if i == 1:
        print(f"Signature: {signature}")
        print(f"Length of signature items: {len(signature)}")
        print(f"Signature verified: {r.verify(message, signature)}")
