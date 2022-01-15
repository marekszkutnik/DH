p = 28151


def order(g, p):
    for i in range(2, p):
        #  subgroup H = Fp, i.e., every element of Fp, can be written as g^n mod p for some integer n
        if pow(g, i, p) == g:
            return i
    return p


for g in range(2, p):
    o = order(g, p)
    if o == p:
        print("Result: ", g)
        break  # find the smallest element g

# output: 7
