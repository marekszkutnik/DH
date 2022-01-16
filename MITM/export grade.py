import json
import pwn
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse, GCD


def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


def dlog(g, t, p):
    # l such that g**l == t (mod p), with p prime
    # algorithm due to Crandall/Pomerance "Prime Numbers" sec 5.2.2
    def f(xab):
        x, a, b = xab[0], xab[1], xab[2]
        if x < p / 3:
            return [(t * x) % p, (a + 1) % (p - 1), b]
        if 2 * p / 3 < x:
            return [(g * x) % p, a, (b + 1) % (p - 1)]
        return [(x * x) % p, (2 * a) % (p - 1), (2 * b) % (p - 1)]

    i, j, k = 1, [1, 0, 0], f([1, 0, 0])
    while j[0] != k[0]:
        # if i % 1000000 == 0:
            # print(i, j, k)
        i, j, k = i + 1, f(j), f(f(k))
    # print(i, j, k)
    d = GCD(j[1] - k[1], p - 1)
    if d == 1: return ((k[2] - j[2]) % (p - 1) * inverse((j[1] - k[1]) % (p - 1), p - 1)) % (p - 1)
    m, l = 0, ((k[2] - j[2]) % ((p - 1) // d) * inverse((j[1] - k[1]) % ((p - 1) // d), (p - 1) // d)) % ((p - 1) // d)
    while m <= d:
        # print(m, l)
        if pow(g, l, p) == t: return l
        m, l = m + 1, (l + ((p - 1) // d)) % (p - 1)
    return None


# MAIN PROGRAM

HOST = "socket.cryptohack.org"
PORT = 13379

conn = pwn.remote(HOST, PORT)

data = conn.recvline().decode()
# Intercepted from Alice: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}

new_supported = '{"supported": ["DH64"]}'

data = json.loads(new_supported)
# {'supported': ['DH1536', 'DH1024', 'DH512', 'DH256', 'DH128', 'DH64']}
# {'supported': ['DH64']}

conn.send(json.dumps(data))

data = conn.recvline().decode()
# Send to Bob: Intercepted from Bob: {"chosen": "DH64"}

data = json.loads(data.removeprefix("Send to Bob: Intercepted from Bob: "))
# {'chosen': 'DH64'}

conn.send(json.dumps(data))

data = conn.recvline().decode()
# Send to Alice: Intercepted from Alice: {"p": "0xde26ab651b92a129", "g": "0x2", "A": "0x3e2e5065a67f484e"}

data = json.loads(data.removeprefix("Send to Alice: Intercepted from Alice: "))
# {'p': '0xde26ab651b92a129', 'g': '0x2', 'A': '0xa713a6ddfab6ef3e'}

p = int(data["p"], 16)
# 16007670376277647657
g = int(data["g"], 16)
# 2
A = int(data["A"], 16)
# 13943818912534842710

conn.send(json.dumps(data))

data = conn.recvline().decode()
# Intercepted from Bob: {"B": "0x563e3064b6463ded"}

data = json.loads(data.removeprefix("Intercepted from Bob: "))
# {'B': '0x563e3064b6463ded'}

B = int(data["B"], 16)
# 8171431358634425125

conn.send(json.dumps(data))

# Receive iv and encrypted flag and decrypt
data = conn.recvline().decode()
# Intercepted from Alice: {"iv": "3b1395a2ed58c381e467825e70235fad", "encrypted_flag": "e9d0a8f2e8d640abb4ba292fd7aa7f7e5a560455563f3cca17c3373334d992a6"}

data = json.loads(data.removeprefix("Intercepted from Alice: "))
# {'iv': '7b50c95624a9dc982ccde010f938344d', 'encrypted_flag': '7da8ebb2e773637b8a6f190ea963ae6114b03aa7f77707794b8f51d12015f9e9'}

iv = data["iv"]
ciphertext = data["encrypted_flag"]

# Use Discrete logarithm calculator https://www.alpertron.com.ar/DILOG.HTM to find out Alice's secret key ``a``
# Example: Find the number n such that 7^n ≡ 23 (mod 43241).
# Type 7 in the Base input box, 23 in the Power input box and 43241 in the Mod input box. Then press the button named "Discrete logarithm".

# a = dlog(g, A, p)  # runs for a couple of hours
a = dlog(g, A, p)

shared_secret = pow(B, a, p)

print("Result: ", decrypt_flag(shared_secret, iv, ciphertext))

# output: crypto{d0wn6r4d35_4r3_d4n63r0u5}
