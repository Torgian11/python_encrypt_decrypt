from typing import Tuple, List
import random

def is_prime(n, k=40):
    """ Miller-Rabin primality test """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def prime_generator(bits):
    """ Generate a prime number of `bits` bits. """
    while True:
        prime_candidate = random.getrandbits(bits)
        prime_candidate |= (1 << bits - 1) | 1
        if is_prime(prime_candidate):
            return prime_candidate

def ext_euclidian_alg(a, b):
    """ Extended Euclidean Algorithm to find the modular inverse. """
    if a == 0:
        return (0, 1, b)
    else:
        x, y, gcd = ext_euclidian_alg(b % a, a)
        return (y - (b // a) * x, x, gcd)

def fast_exponentiation(base, exp, mod):
    """ Fast exponentiation algorithm for modular arithmetic. """
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


class RSA:
    def __init__(self, key_size: int):
        self._key_size: int = key_size
        self._chunk_size: int = key_size // 8
        self._public_key: Tuple[int, int] | None = None
        self._private_key: Tuple[int, int] | None = None
        self._generate_keys(prime_generator(self._key_size), prime_generator(self._key_size))

    @property
    def public_key(self) -> Tuple[int, int]:
        return self._public_key

    @property
    def private_key(self) -> Tuple[int, int]:
        return self._private_key

    def _generate_keys(self, p: int, q: int):
        n: int = p * q
        phi: int = (p - 1) * (q - 1)
        # e: int = random.choice([i for i in range(1, phi) if gcd(i, phi) == 1])
        e = 65537
        d = ext_euclidian_alg(e, phi)[0]
        if d < 0:
            d += phi

        self._public_key = (e, n)
        self._private_key = (d, n)

    def encrypt(self, text: str) -> List[int]:
        chunks = self._split_text(text)
        encrypted_chunks = [fast_exponentiation(chunk, self._public_key[0], self._public_key[1]) for chunk in chunks]
        return encrypted_chunks

    def decrypt(self, cipher: List[int]) -> str:
        decrypted_chunks = [fast_exponentiation(chunk, self._private_key[0], self._private_key[1]) for chunk in cipher]
        return self._assemble_text(decrypted_chunks)

    # def encrypt(self, text: str) -> List[int]:
    #     cipher_blocks = []
    #     bytesarray = bytearray(text.encode('UTF-8'))
    #     for i in range(0, len(bytesarray), self._chunk_size):
    #         block = bytesarray[i:i + self._chunk_size]
    #         integer = int.from_bytes(block, byteorder='big', signed=False)
    #         cipher_blocks.append(fast_exponentiation(integer, self._public_key[0], self._public_key[1]))
    #     return cipher_blocks

    # def decrypt(self, cipher_blocks: List[int]) -> str:
    #     decrypted_bytes = bytearray()
    #     for block in cipher_blocks:
    #         integer = fast_exponentiation(block, self._private_key[0], self._private_key[1])
    #         block_bytes = integer.to_bytes(length=self._chunk_size, byteorder='big', signed=False)
    #         decrypted_bytes.extend(block_bytes)
    #     return decrypted_bytes.decode('UTF-8')


    # @staticmethod
    # def encrypt_with_key(text: str, key: Tuple[int, int], chunk_size: int) -> List[int]:
    #     cipher_blocks = []
    #     bytesarray = bytearray(text.encode('UTF-8'))
    #     for i in range(0, len(bytesarray), chunk_size):
    #         block = bytesarray[i:i + chunk_size]
    #         integer = int.from_bytes(block, byteorder='big', signed=False)
    #         cipher_blocks.append(fast_exponentiation(integer, key[0], key[1]))
    #     return cipher_blocks

    # @staticmethod
    # def decrypt_with_key(cipher_blocks: List[int], key: Tuple[int, int], chunk_size: int) -> str:
    #     decrypted_bytes = bytearray()
    #     for block in cipher_blocks:
    #         integer = fast_exponentiation(block, key[0], key[1])
    #         block_bytes = integer.to_bytes(length=chunk_size, byteorder='big', signed=False)
    #         decrypted_bytes.extend(block_bytes)
    #     return decrypted_bytes.decode('UTF-8')
    @staticmethod
    def encrypt_with_key(text: str, key: Tuple[int, int]) -> List[int]:
        rsa = RSA(key_size=8 * (key[1].bit_length() // 8 + 1))
        chunks = rsa._split_text(text)
        encrypted_chunks = [fast_exponentiation(chunk, key[0], key[1]) for chunk in chunks]
        return encrypted_chunks

    @staticmethod
    def decrypt_with_key(cipher: List[int], key: Tuple[int, int]) -> str:
        rsa = RSA(key_size=8 * (key[1].bit_length() // 8 + 1))
        decrypted_chunks = [fast_exponentiation(chunk, key[0], key[1]) for chunk in cipher]
        return rsa._assemble_text(decrypted_chunks)

    def _split_text(self, text: str) -> List[int]:
        bytesarray = bytearray(text.encode('UTF-8'))
        chunks = []
        for i in range(0, len(bytesarray), self._chunk_size):
            chunk = bytesarray[i:i + self._chunk_size]
            chunk_int = int.from_bytes(chunk, byteorder='big', signed=False)
            chunks.append(chunk_int)
        return chunks

    def _assemble_text(self, chunks: List[int]) -> str:
        bytesarray = bytearray()
        for chunk in chunks:
            chunk_bytes = chunk.to_bytes((chunk.bit_length() + 7) // 8, byteorder='big')
            bytesarray.extend(chunk_bytes)
        return bytesarray.decode('UTF-8')


rsa = RSA(2048)

# Encrypting a message
message = "This is a secret message."
encrypted_blocks = rsa.encrypt(message)
print("Encrypted blocks:", encrypted_blocks)

# Decrypting the message
decrypted_message = rsa.decrypt(encrypted_blocks)
print("Decrypted message:", decrypted_message)
              
