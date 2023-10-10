import sys

def djb2HashA(str):
    hash = 8191
    for c in str:
        hash = ((hash << 5) + hash) + ord(c)
    return hash & 0xFFFFFFFF

# Examples:
print(hex(djb2HashA(sys.argv[1]))) # 0xc25aaa07
