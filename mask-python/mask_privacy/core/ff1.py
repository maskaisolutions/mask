import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class FF1:
    """NIST SP 800-38G Format-Preserving Encryption (FF1)."""
    
    def __init__(self, key: bytes, tweak: bytes, radix: int):
        self.key = key
        self.tweak = tweak
        self.radix = radix
        self.backend = default_backend()
        self.chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        if radix > len(self.chars):
            raise ValueError(f"Radix {radix} not supported")

    def _prf(self, X: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(b'\x00' * 16), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(X)[-16:]

    def _ciph(self, X: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(X)

    def _str_to_int(self, s: str) -> int:
        n = 0
        for char in s:
            n = n * self.radix + self.chars.index(char)
        return n

    def _int_to_str(self, num: int, length: int) -> str:
        if num == 0:
            return self.chars[0] * length
        digits = []
        while num > 0:
            digits.append(self.chars[num % self.radix])
            num //= self.radix
        s = "".join(reversed(digits))
        return s.rjust(length, self.chars[0])

    def encrypt(self, X: str) -> str:
        n = len(X)
        t = len(self.tweak)
        if n < 2: return X
        u = n // 2
        v = n - u
        A = X[:u]
        B = X[u:]
        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4
        
        P = (bytes([1, 2, 1]) + 
             self.radix.to_bytes(3, 'big') + 
             bytes([10, u % 256]) + 
             n.to_bytes(4, 'big') + 
             t.to_bytes(4, 'big'))
             
        for i in range(10):
            m = u if i % 2 == 0 else v
            pad_len = (-t - b - 1) % 16
            Q = self.tweak + bytes(pad_len) + bytes([i]) + self._str_to_int(B).to_bytes(b, 'big')
            R = self._prf(P + Q)
            S = R
            j = 1
            while len(S) < d:
                xor_block = bytes(x ^ y for x, y in zip(R, j.to_bytes(16, 'big')))
                S += self._ciph(xor_block)
                j += 1
            S = S[:d]
            y = int.from_bytes(S, 'big')
            modulo = self.radix ** m
            c = (self._str_to_int(A) + y) % modulo
            C = self._int_to_str(c, m)
            A = B
            B = C
        return A + B

    def decrypt(self, X: str) -> str:
        n = len(X)
        t = len(self.tweak)
        if n < 2: return X
        u = n // 2
        v = n - u
        A = X[:u]
        B = X[u:]
        if n % 2 != 0:
            A, B = B, A
            
        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4
        
        P = (bytes([1, 2, 1]) + 
             self.radix.to_bytes(3, 'big') + 
             bytes([10, u % 256]) + 
             n.to_bytes(4, 'big') + 
             t.to_bytes(4, 'big'))

        for i in range(9, -1, -1):
            m = u if i % 2 == 0 else v
            pad_len = (-t - b - 1) % 16
            Q = self.tweak + bytes(pad_len) + bytes([i]) + self._str_to_int(A).to_bytes(b, 'big')
            R = self._prf(P + Q)
            S = R
            j = 1
            while len(S) < d:
                xor_block = bytes(x ^ y for x, y in zip(R, j.to_bytes(16, 'big')))
                S += self._ciph(xor_block)
                j += 1
            S = S[:d]
            y = int.from_bytes(S, 'big')
            modulo = self.radix ** m
            c = (self._str_to_int(B) - y) % modulo
            C = self._int_to_str(c, m)
            B = A
            A = C
            
        if n % 2 != 0:
            A, B = B, A
            
        return A + B
