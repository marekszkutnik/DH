from Crypto.Util.number import inverse

g = 209
p = 991

result = inverse(g, p)

print("Result: ", result)

# output: 569
