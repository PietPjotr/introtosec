### here are the test used to test all the functions independently
def test_subbytes():
    msg = 'S'
    bytearr = bytearray(msg, 'utf-8')
    padded = pad(bytearr)
    print(padded)
    matrix = bytes_to_matrix(padded)

    subbed = subbytes_word(matrix)
    print(subbed)
    print(0xED)


def convertiontest():
    test = [i for i in range(16)]
    test = bytearray(test)
    matrix = bytes_to_matrix(test)
    for el in matrix:
        print(el)
    back = matrix_to_bytes(matrix)
    print(test)
    print(back)


def padtest():
    pt = "hello"
    bytearr = bytearray(pt, 'utf-8')
    padded = pad(bytearr)
    print(padded)
    print(len(padded))

def shiftrowtest():
    test = [i for i in range(16)]
    test = bytearray(test)
    matrix = bytes_to_matrix(test)
    res = shiftrow_word(matrix)
    print(np.asmatrix(matrix))
    print()
    print(np.asmatrix(res))

# test vectors from https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
def mixcolumnstest():
    test1 = [[0xdb, 0xf2, 0x01, 0xc6],
            [0x13, 0x0a, 0x01, 0xc6],
            [0x53, 0x22, 0x01, 0xc6],
            [0x45, 0x5c, 0x01, 0xc6]]

    test2 = [[0x01, 0xc6, 0xd4, 0x2d],
             [0x01, 0xc6, 0xd4, 0x26],
             [0x01, 0xc6, 0xd4, 0x31],
             [0x01, 0xc6, 0xd5, 0x4c]]

    mixColumns(test2)


def expandkeytest():
    key = '2b7e151628aed2a6abf7158809cf4f3c'
    key = bytearray.fromhex(key)

    keys = expandKey(key)
    for i in range(len(keys)):
        word = keys[i]
        heks = bytes_to_hex(word)
        print("i = {}.: ".format(i + 1))
        print(heks)
        print()
        