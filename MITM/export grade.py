import json
import pwn
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# from Crypto.Util.number import inverse, GCD


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


# def dlog(g, t, p):
#     # l such that g**l == t (mod p), with p prime
#     # algorithm due to Crandall/Pomerance "Prime Numbers" sec 5.2.2
#     def f(xab):
#         x, a, b = xab[0], xab[1], xab[2]
#         if x < p / 3:
#             return [(t * x) % p, (a + 1) % (p - 1), b]
#         if 2 * p / 3 < x:
#             return [(g * x) % p, a, (b + 1) % (p - 1)]
#         return [(x * x) % p, (2 * a) % (p - 1), (2 * b) % (p - 1)]
#
#     i, j, k = 1, [1, 0, 0], f([1, 0, 0])
#     while j[0] != k[0]:
#         if i % 1000000 == 0:
#             print(i, j, k)
#         i, j, k = i + 1, f(j), f(f(k))
#     print(i, j, k)
#     d = GCD(j[1] - k[1], p - 1)
#     if d == 1: return ((k[2] - j[2]) % (p - 1) * inverse((j[1] - k[1]) % (p - 1), p - 1)) % (p - 1)
#     m, l = 0, ((k[2] - j[2]) % ((p - 1) // d) * inverse((j[1] - k[1]) % ((p - 1) // d), (p - 1) // d)) % ((p - 1) // d)
#     while m <= d:
#         print(m, l)
#         if pow(g, l, p) == t: return l
#         m, l = m + 1, (l + ((p - 1) // d)) % (p - 1)
#     return None


# MAIN PROGRAM

HOST = "socket.cryptohack.org"
PORT = 13379

conn = pwn.remote(HOST, PORT)

data = conn.recvline().decode()
# Intercepted from Alice: {"supported": ["DH1536", "DH1024", "DH512", "DH256", "DH128", "DH64"]}

data = json.loads(data.removeprefix("Intercepted from Alice: "))
# {'supported': ['DH1536', 'DH1024', 'DH512', 'DH256', 'DH128', 'DH64']}

conn.send(json.dumps(data))

data = conn.recvline().decode()
# Send to Bob: Intercepted from Bob: {"chosen": "DH1024"}

data = json.loads(data.removeprefix("Send to Bob: Intercepted from Bob: "))
# {'chosen': 'DH1024'}

conn.send(json.dumps(data))

data = conn.recvline().decode()
# Send to Alice: Intercepted from Alice: {"p": "0xf2639ce2bdb2e67154813bcbda8e5a09ddaa1235c5e76300602e29ada9dd6dfddf36b3c6a676891ddb1462de67cc27a45f84d8720b8bfdcb653c82814397998e84aafca63a8b4ae05d3193e7566173441d505dc3caea006f938d421de7e80748297496436e559fe9c443201de066cd7570a8a40c80a306309dfb4da48277858b", "g": "0x2", "A": "0x6a73a93675e1ff9ebef0b52383fd517c5b10d910ec8b54356dfdf17c1c6f217726cb6e884bafa3ae7b81daf82de7c683651529197676aed3b294ce9cf4629caf1c645f4b5d9fe403d6f5b3cad92e5fcaf1d3aa8aa69c99c31dc65dbbd1230889ca0e4fdc4e0bb3e6d2f21d06268e0626a1416992edfb2ad8d1854aa7a0b4e5bf"}

data = json.loads(data.removeprefix("Send to Alice: Intercepted from Alice: "))
# {'p': '0xf2639ce2bdb2e67154813bcbda8e5a09ddaa1235c5e76300602e29ada9dd6dfddf36b3c6a676891ddb1462de67cc27a45f84d8720b8bfdcb653c82814397998e84aafca63a8b4ae05d3193e7566173441d505dc3caea006f938d421de7e80748297496436e559fe9c443201de066cd7570a8a40c80a306309dfb4da48277858b', 'g': '0x2', 'A': '0x3c6799fca39bb24ff3ba0470faa26073817504cb2c18035721fb65144d480cec30538fc5b150e67d1169ca0c7bbd8b1b6fda6ce4a577d7eda7d1401a05a144883d62019004fb6902350d7ff305b74776ceda555db27078831f5d78dce31886966caa16ff7e8efb92a5dbfaffbcb10c4408df5fa497b33b85575c508d0c2dd7be'}

p = int(data["p"], 16)
# 170211423340213335619890315701964596367945248276514520244678817439067130096324998127511342969908892058912749484588982313397564275823569054303745334070068855198518744024716272819605925778992568884399647476753727321262120112574453697534597065598599870833667305595574803533448657324362004298384951750848679478667
g = int(data["g"], 16)
# 2
A = int(data["A"], 16)
# 82712171545638217159725079659112592839979959675510229957620802725313183041981241004674971774163261888377336317428092459046646743047797698140802527596634615546381180792847692929532331869204323980435512792350216054315511990954380608923323932989759247337027388682669206668087549195465748790166785023890355094165


conn.send(json.dumps(data))

data = conn.recvline().decode()
# Intercepted from Bob: {"B": "0x8a78b68300b27edf6cfc82c1b3d8412179af029b168987718b15c83a358a26759cf0da25b52343ae701a73bd280da2c5fa8bf4a99acb083c515f2279b0530efa131792b34e606c47f8af7054e7bae1056e48cd83b602d472a0bdc6defc7a1915737677cf4087ec8c16ff1e678cef8438400d1191d1b7754103d4c03221882ec1"}

data = json.loads(data.removeprefix("Intercepted from Bob: "))
# {'B': '0x38e7a6368a2f19189102c2a87a1068369d534a730418d7ea5dedef7b374d8d639f037fc1940ec448fd6597d33a4378ffa73741eed30593e07137def773ad5adebcb40725d05f76076b3a65155f20e8d4b80d724c419d1ae2244189e383ee32480bc7fad2af0553f7aab8e56294147a6bb12774caaa0cfb6b87d5df8b8743ef11'}

B = int(data["B"], 16)

conn.send(json.dumps(data))

# Receive iv and encrypted flag and decrypt
data = conn.recvline().decode()
# Intercepted from Alice: {"iv": "fc4daf1ff7cbcc709e138ecc1ec9b9b6", "encrypted_flag": "fb02be36826ba1cbf3a62631515e64f9f6af40453d8fb2327d3ccf1c44a96639"}

data = json.loads(data.removeprefix("Intercepted from Alice: "))
# {'iv': '56187c7ec00645f920d6d453364acd3b', 'encrypted_flag': '329d35cdf224805677bf8f9a0a1e55d96914e6ae5247cc9158d39ef7c0bc7a86'}

iv = data["iv"]
ciphertext = data["encrypted_flag"]

# Use Discrete logarithm calculator https://www.alpertron.com.ar/DILOG.HTM to find out Alice's secret key ``a``
# a = dlog(g, A, p)  # runs for a couple of hours
a =

shared_secret = pow(B, a, p)

print("Result: ", decrypt_flag(shared_secret, iv, ciphertext))

# output: crypto{n1c3_0n3_m4ll0ry!!!!!!!!}
