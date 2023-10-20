# authors:      Pjotr Piet, Stefano jonjic
# university:   UvA
# course:       Introduction to security
# student id's: 12714933, 13237594
# description:  This file contains a proper implementation of the AES as
#  documented in: https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
#  AES uses a key and different non-lineair functions to encrypt and decrypt
#  plaintext. First the key is applied to the plaintext. Then for this
#  application of AES (128-bit), 10 rounds are applied to the plaintext. These
#  rounds consist of substituting the values of the bytes using a substituting
#  table. Then the rows are shifted in a specific manner. Then the columns are
#  shifted in a specific manner. Lastly, at the end of each round anohter key
#  is applied that is created by expanding the original key. At the end of the
#  10 rounds, one more 'round' is applied to the text except that this round
#  does not include the mixing of the columns. Then the encryption is done.


sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def pad(msg):
    """
    Gets the plaintext in bytes and pads it using the PKCS#7 padding. This
    means that multiples of 16 will get an entire block of value 0xF added.
    """
    padding = 16 - (len(msg) % 16)
    for i in range(padding):
        msg.append(padding)
    return msg


def bytes_to_matrix(bytes):
    """Converts a bytearray to a matrix according to the specification for AES,
    aka columnwise convertion."""
    return [[bytes[i], bytes[i+4], bytes[i+8], bytes[i+12]] for i in range(4)]


def matrix_to_bytes(matrix):
    """Turn the matrix back into a bytearray."""
    arr = []
    for i in range(4):
        for j in range(4):
            arr.append(matrix[j][i])
    return bytearray(arr)


def subBytes(state):
    """Substitutes the bytes according to the sbox table. The value of each
    byte in the state becomes the value at index state_value in the sbox."""
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]

    return state


def shiftRow(state):
    """
    Shift the rows of a single word according to the official AES
    documentation. The first row is left the same, the second row is shifted by
    rotating the first element to the end of the row. And for the second row
    the first two and first three.
    """
    for i in range(4):
        state[i] = [state[i][(i+j) % 4] for j in range(4)]

    return state


def gmul(a, b):
    """Handles the multiplication and modulo operation as explained in:
    https://en.wikipedia.org/wiki/Rijndael_MixColumns using Rijndaels GF(2)."""
    if b == 1:
        return a
    tmp = (a << 1) & 0xff
    if b == 2:
        return tmp if a < 128 else tmp ^ 0x1b
    if b == 3:
        return gmul(a, 2) ^ a


def mixColumn(col):
    """Implementation inspired by:
    https://stackoverflow.com/questions/66115739/aes-mixcolumns-with-python
    alters the values of the given col to the proper values according to the
    AES specifications for the mixCol function."""
    [c1, c2, c3, c4] = col
    r1 = gmul(c1, 2) ^ gmul(c2, 3) ^ gmul(c3, 1) ^ gmul(c4, 1)
    r2 = gmul(c1, 1) ^ gmul(c2, 2) ^ gmul(c3, 3) ^ gmul(c4, 1)
    r3 = gmul(c1, 1) ^ gmul(c2, 1) ^ gmul(c3, 2) ^ gmul(c4, 3)
    r4 = gmul(c1, 3) ^ gmul(c2, 1) ^ gmul(c3, 1) ^ gmul(c4, 2)

    return [r1, r2, r3, r4]


def mixColumns(state):
    for i in range(4):
        [state[0][i], state[1][i], state[2][i], state[3][i]] = \
         mixColumn([state[0][i], state[1][i], state[2][i], state[3][i]])
    return state


# https://uomustansiriyah.edu.iq/media/lectures/5/5_2021_06_05!07_10_53_PM.pdf
def rotWord(word):
    """Aplies one left-rotation to the given word."""
    return [word[1], word[2], word[3], word[0]]


def subWord(word):
    """Substitutes one word according to the xbox table."""
    return [sbox[word[i]] for i in range(4)]


def xorBytes(a, b):
    """Takes two words and performs an xor on all the bytes."""
    ret = []
    for i in range(4):
        ret.append(a[i] ^ b[i])
    return ret


def expandKey(key):
    """Expands the key according to the key expansion algorithm as described in
    the official nist documentation."""
    w = []
    for i in range(4):
        w.append(key[4*i:4*i+4])

    for i in range(3, 43):
        temp = w[i]
        if (i + 1) % 4 == 0:
            temp = subWord(rotWord(temp))
            temp[0] = temp[0] ^ rcon[int((i + 1) / 4)]

        next_word = xorBytes(temp, w[i - 3])
        w.append(next_word)

    return w


def printKeys(keys):
    """Helper function for printing all the keys in a nice way."""
    res = ""
    for i in range(11):
        res += "Round {}: ".format(i)
        for j in range(4):
            for k in range(4):
                res += (str(hex(keys[4*i + j][k])[2:]) + ' ')
        res += '\n'
    print(res)


def key_to_bytes(key):
    """Flattens the round key so that it can be added to the state."""
    ret = []
    for i in range(4):
        for j in range(4):
            ret.append(key[i][j])
    return bytearray(ret)


def addRoundKey(cipher, key):
    """Adds the round key to the given ciphertext."""
    cipher = [el for el in cipher]
    return bytearray([a ^ b for (a, b) in zip(cipher, key)])


def bytes_to_hex(inp):
    """Converts bytes to hexadecimal string."""
    heks = ''
    for el in inp:
        if len(str(hex(el))) == 4:
            heks += str(hex(el))[2:]
        else:
            heks += '0' + str(hex(el))[-1]
    return heks


def encrypt(pt, key):
    """
    pt: the given plaintext in string form
    key: the given key in string form

    out: the cipher in hexadecimal string

    Firstly the plaintext gets padded and the amount of sections are
    calculated. Then the round keys are expanded and the key for round 0 gets
    determined and added to the plaintext, this is now the state.
    Then for all 9 rounds the state gets substituted with the values in the
    sbox, then the rows gets shifted, then the columns get mixed, and lastly
    the round key for that round gets added (xor'ed) with the state.
    Lastly one more round gets performed except for the mixColumns.

    All encrypted sections then get concatenated for the final result."""

    pt = bytearray(pt, 'utf-8')
    key = bytearray(key, 'utf-8')

    pt = pad(pt)

    if len(key) != 16:
        print("The given key is not the right size, exiting the encryption.")
        return

    sections = int(len(pt) / 16)

    keys = expandKey(key)
    init_key = [byte for word in keys[0:4] for byte in word]
    cipher = b''

    for i in range(sections):

        state = addRoundKey(pt[16*i: 16*i + 16], init_key)

        for j in range(1, 10):
            state = bytes_to_matrix(state)
            state = subBytes(state)
            state = shiftRow(state)
            state = mixColumns(state)
            state = addRoundKey(matrix_to_bytes(state),
                                key_to_bytes(keys[4*j:4*j + 4]))

        state = bytes_to_matrix(state)
        state = subBytes(state)
        state = shiftRow(state)
        state = addRoundKey(matrix_to_bytes(state),
                            key_to_bytes(keys[4*(j+1):4*(j+1) + 4]))

        cipher += state

    return cipher


def main():
    key = 'Burden Of Dreams'
    plaintext = 'Dit is een hele lange test tekst om te testen of de padding ook werkt voor grotere teksten zoals deze. Een mooie testtekst dus.'

    cipher = encrypt(plaintext, key)

    heks = bytes_to_hex(cipher)
    print(heks.upper())


if __name__ == "__main__":
    main()
