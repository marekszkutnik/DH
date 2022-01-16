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
PORT = 13379

connection = pwn.remote(HOST, 13373)
connection.recvuntil(b'Intercepted from Alice: ')

# Alice sends p, g, A
from_alice = json.loads(connection.recvline())
p_hex = from_alice['p']
g_hex = from_alice['g']
A_hex = from_alice['A']

# Bob sends B
connection.recvuntil(b'Intercepted from Bob: ')
B_hex = json.loads(connection.recvline())['B']

# Alice sends iv, encrypted
connection.recvuntil(b'Intercepted from Alice: ')
content = json.loads(connection.recvline())

iv = content['iv']
encrypted_flag = content['encrypted']


# Trick :
# Send A as g to Bob
# Bob thinking that he is calculating B in fact calculates s and sends it to us
to_bob = {"p": p_hex, "g": A_hex, "A": '0x1'}

# send prepared message to Bob
connection.sendline(json.dumps(to_bob))
connection.recvuntil(b'Bob says to you: ')

B_hex = json.loads(connection.recvline())['B']


# Bob send us B, but it is shared_secret in fact
shared_secret = int(B_hex, 16)

print("Result: ", decrypt_flag(shared_secret, iv, encrypted_flag))

# output: crypto{n07_3ph3m3r4l_3n0u6h}
