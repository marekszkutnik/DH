import json
import pwn
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse


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


# MAIN PROGRAM

HOST = "socket.cryptohack.org"
PORT = 13380

conn = pwn.remote(HOST, PORT)

data = conn.recvline().decode()
# Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0x7aa60dd5a5ab56a9385caa01e6889ec64c982de08be3ee347f1474bf3094fc2d9973107b90ae75998a2d73dd6140832596e0fe41d1ff142b5d419ff98ee791ff0360d377f9199d67fb92cab030c67fbd6595111822be7f4c7d3d8260e38632534d78e27fadae7e500c6a8f07fef71d2f8671f5b85b8ee4a03e55bf855cd41f12930b8c52554a602df9e44629b4ceae13b836206b6d545284a40d3168556ccbd1d1e405a47650caeea520df21797d76ab8cd9eafc3a09038e6be254e9bf416fbe"}

data = json.loads(data.removeprefix("Intercepted from Alice: "))
# {'p': '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 'g': '0x02', 'A': '0xe55ec9ba5622ee52d23a5ef86eb6f013569da156d156d699b4754dd50f5250ad80f788882bdda51aaedf0c3ff5c43b21d67cdd345139cbd84859944688b3ff59306f84c41e269996d87f1c6612cf6a8bf1999fc6f20c824199f81a0a03e24f5a034254a3f1b72f81833e8146954ff20d5725f346dfd7f104763b39a385c918eafc8784f6fa22015030cbdadcca40e361daf3de2324c4f3f654d104e926f5eeb1122c02e5293b1582afbb66b88df0a195758e28ea2b3c6693e448f36d10e98ed1'}

p = int(data["p"], 16)
g = int(data["g"], 16)
A = int(data["A"], 16)

conn.send(json.dumps(data))

data = conn.recvline().decode()
# Intercepted from Bob: {"B": "0x3f73d168459181a2c92e7a9f6853034fd5f0fb09e1fb609985b12a313768f9f02d0cfccb8794aed90a316423386a83fe27dc2ebccc5467175be74212cc803e8ef85f38e6eaddbfcd1dfb50977bac6f2f75d6c0467997d4ada0b745b9b4cca3beb1e055385275859b139f113f6e5a2681d9bc083d5f9ed2189c87d85011b6aab6b548667afa830f18bca8d3278ab8ce3efd5db8cc591873f6d57032e699c5534d197e09270f4cdde97ce55b744710bb0427486214c9ecd1cde098e721dc28fe26"}

data = json.loads(data.removeprefix("Intercepted from Bob: "))
# {'B': '0x31cb654eb37354a0bb3db1ce003f997b23e7f460b1912cf73faea130c0af1c89dbb03fe62056e9e8984145e3ba88acd6fc42c5eb8c0243ec7280b9a5903164c1c90094a8114ba0904be149b6d76cb25fe0d779721e528ab04bf602cbd65f0826e198ee48ca6740c2d5888750e84f3d59098982c586db9f5049ae66941ad7c956008fac3bef5bab958b422ff50c9c246b980764e3c8720c15c50c45f55d1c288689b84aacca048dd874912a3260f15c0229ef67201c975ec68b2a4be7fd66ada7'}

B = int(data["B"], 16)

conn.send(json.dumps(data))

# Receive iv and encrypted flag and decrypt
data = conn.recvline().decode()
# Intercepted from Alice: {"iv": "28b2574afa3d1279bdf7ab8a0cf2b63e", "encrypted": "787d831d2c784d72ea4b1f177b2c43633f4453e1eca143ed6cfd5834b62e6e7097be6b1af24d2297f5c1c8b4eab1f9c4"}

data = json.loads(data.removeprefix("Intercepted from Alice: "))
# {'iv': '3ba206fd8cb2f13f360476c026c8da88', 'encrypted': '1ec1e2b525c226aae1081bb35afc6ddd6e1ff5720b783e0abe0d419d053a6ba8c49bc29e7fff85b0758d61bd5ff08231'}

iv = data["iv"]
ciphertext = data["encrypted"]

a = A * inverse(g, p)  # inverse(u, v) - Return the inverse of u mod v.
shared_secret = B * a % p

print("Result: ", decrypt_flag(shared_secret, iv, ciphertext))

# output: crypto{cycl1c_6r0up_und3r_4dd1710n?}
