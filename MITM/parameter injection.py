import json
import pwn
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


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
PORT = 13371

conn = pwn.remote(HOST, PORT)

data = conn.recvline().decode()
# Intercepted from Alice: {"p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "g": "0x02", "A": "0x481798f4112ac12cbb6bcc4e671c4cdc145321bebe2a4a89ded6fc5660534bc1b083b77aa09e93aa726b6e69409b276a67ec2c3c0215ed7f6fe140440c15cfb8b3578d6604759ced743f48705f6cdf6519f0ae2e946ef88fd961ce1f6d3836abb7fd0802a5c65fe8bd5f6928369e57cfb8ddddf02b03970512873d48be6b5b8a62f5e08bfcb102785ee59c03633b2d46a28cb3a8e96f9121a2f1e11d293ad2452e6feafc58d8fa840a691d1ff9fd13397bca472da3c667532c95d6ca898d7d41"}

data = json.loads(data.removeprefix("Intercepted from Alice: "))
# {'p': '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 'g': '0x02', 'A': '0x2773eb9bf0613845a2b109e23e53fc16a2feecaf12f13f1769d9a78b43041aefc460ec47c3f7378ce2f52af096a11b225b282045fe9e090a3c801ddcdad070a27958def8d0cc9513e40555d29d5107ca771551a24ae592f8fed0f4d96777ee28a88bce7328523a257fa130e182fffab0408acda5765c760fd287e273944f3496d465f6091e75162daf873da6786c4585a83e649d2f425cb5d342ce3926865bc67675cb8b2099af8fc5f8144bf4f00cac48fd847b90f9539bd735461491be70ef'}

p = int(data["p"], 16)
g = int(data["g"], 16)
A = int(data["A"], 16)

resp = dict()
resp["p"] = hex(p)
resp["g"] = hex(g)
# We tell B that A = p
resp["A"] = hex(p)

conn.send(json.dumps(resp))

data = conn.recvline().decode()
# Send to Bob: Intercepted from Bob: {"B": "0x2b7645a1d336e4498da21c471e83e1255759c00ed67727fc545a4740ad4f8fabd3d352cf631dd56bb6d0f7d3321b82aabbd66d1568e35ffe6d517245be543619d9a5bea728a2d3e5189abc7ecf350f0abcd8009862e4aef39280f6f21b335cbf39fb09cff9413aa5aa03e80f5ca82f63328228ba937c2c5e78bb3440f61dbe218d67dd5b8a69f4f8419ce3f19fe575f2ca0d9549dd4512676d10aa308901f6e03844d7eb3e6f4f00cd1543300b82bf6857cf3052afab795ba9140143827147a8"}

data = json.loads(data.removeprefix("Send to Bob: Intercepted from Bob: "))
# {'B': '0x7fa2fe6601b3d756c9fd1beca6c90506fc8ca95d40d4801ac07cc31b91374b1b04dc50b36b6ba5eb1b565883e587e333ab9c866cdc393fee84577e870e2c39281eafe4e81eec2cd1e8b80a2a21d2a5f0c922a2db45a56fb76c7cd2033839f110dce20a3f430245a2e422cde7fc0c307cbb5f08a0975245cbd5bcf9baa44a6606d4e9c6bada06100ed52ae5dfae395d123b50c503f1ca39777438e3778c567f623da06d3c392b8c1f68e58e91fe31e6f6e069a64bbf3753297adf9b74380a3365'}

resp = dict()
B = int(data["B"], 16)
# We tell A that B = p
resp["B"] = hex(p)

conn.send(json.dumps(resp))

# Receive iv and encrypted flag and decrypt
data = conn.recvline().decode()
# Send to Alice: Intercepted from Alice: {"iv": "9e2743d9b8f2701b14f919f136fe3867", "encrypted_flag": "464e93d9d58b1100f892f012f2f12a767df19eaef1f1202a43c23f52642d9670"}

data = json.loads(data.removeprefix("Send to Alice: Intercepted from Alice: "))
# {'iv': '3862bae801443dfc26c354e48bde8741', 'encrypted_flag': '3f0db653585b170e1cf0799d446f06858eff9154995f14df1e2107bd704e2cb9'}

iv = data["iv"]
ciphertext = data["encrypted_flag"]

# It doesn't really matter what the vaule of a or b is
# because we raise p to some power mod p which equals 0
shared_secret = 0
print("Result: ", decrypt_flag(shared_secret, iv, ciphertext))

# output: crypto{n1c3_0n3_m4ll0ry!!!!!!!!}
