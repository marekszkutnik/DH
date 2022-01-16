P = 2
N = 50
E = 31337

FLAG = b'crypto{??????????????????????????}'

def bytes_to_binary(s):
    bin_str = ''.join(format(b, '08b') for b in s)
    bits = [int(c) for c in bin_str]
    return bits

def generate_mat():
    while True:
        msg = bytes_to_binary(FLAG)  # change flag to binary
	    # add padding bits
        msg += [random.randint(0, 1) for _ in range(N*N - len(msg))]

	    # split msg to rows
        rows = [msg[i::N] for i in range(N)]

	    # from rows create matrix 50x50 in GF(2)
        mat = Matrix(GF(2), rows)

        if mat.determinant() != 0 and mat.multiplicative_order() > 10^12:
            return mat

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

def save_matrix(M, fname):
    open(fname, 'w').write('\n'.join(''.join(str(x) for x in row) for row in M))

mat = generate_mat()

ciphertext = mat^E
save_matrix(ciphertext, 'flag.enc')


# SOLUTION

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)


def mat_to_binstr(mat):  # matrix to string
    binstr = ""
    for i in range(N):
        for j in range(N):
            binstr += str(mat[j][i])
    return binstr


c = load_matrix("./flag.enc")

# multiplicative_order() -> tyle razy trzeba pomnozyc macierz przez sama siebie zeby wrocic do takiej samej postaci
mod = c.multiplicative_order()  # ODPOWIEDNIK PHI W RSA

D = pow(E, -1, mod)  # private key

p = pow(c,D)  # c -> matrix

p = mat_to_binstr(p)  # change to string

# get hex from bits string, after 70 mess (padding), before '0x'
pt = hex(int(p, 2))[2:70]

print(bytes.fromhex(pt).decode())  # get bytes and decode