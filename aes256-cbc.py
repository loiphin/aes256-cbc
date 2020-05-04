#!/usr/bin/env python3
#
# A poor mans implementation of AES256-CBC. This is just for fun. 
# If you want a proper AES library, use something like PyCryptodome.
# 
#
# by Simon Bonham - May 2020
#
import hashlib
import random


PASSWORD='SuperSecret'
FILE_BLOCK_SIZE = 16        # 128 bits
KEY_SIZE = 32               # 256 bits
ROUNDS = 10                 # Number of rounds to do. It's 14 in the case of AES256-CBC

# The sbox substitution table
sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

# The inverse sbox substitution table
sboxinv = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]


# rcon table
rcon = [ 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x00, 0xab, 0x00, 0x00, 0x00, 0x4d, 0x00, 0x00, 0x00]


# Open *.dat file and chop the file into 128 bit chunks.
#
def read_file(file):
    f = open(file, 'rb')
    chunk = f.read(FILE_BLOCK_SIZE)
    while chunk:
        padding(chunk)    # Send that particular chunk to be encrypted.
        chunk = f.read(FILE_BLOCK_SIZE)
    f.close()


# PKCS#7 Padding function
# Get the length of padding required, and pad with n number of characters using character n as the pad.
#
def padding(data):
    pad_size = ((FILE_BLOCK_SIZE - len(data)) % FILE_BLOCK_SIZE)
    padded_data = data + (str(pad_size) * pad_size).encode('utf-8')
    pd = list(padded_data)
    print(pd)


# Generate the 256 bit key using SHA256 from the given password
def gen_key(password): 
    h = hashlib.sha256(password.encode('utf-8')).digest()
    key = list(h)
    return key


# Shifts a word (32-bits) n bytes to the left, negative value shifts to the right.
def rotate_word(word, n):
    return word[n:]+word[0:n]


# Read in a 16 byte block of data and substitute according to the sbox table.
def sub_word(block):
    output_bytes = []
    for i in block:
        high, low = i >> 4, i & 0x0F
        #print(hex(high), hex(low))
        output_bytes.append(sbox[16 * high + low])
        #print(output_bytes)
    return output_bytes

# Read in a 16 byte block of data and substitute according to the sboxinv table.
def sub_wordinv(block):
    output_bytes = []
    for i in block:
        high, low = i >> 4, i & 0x0F
        #print(hex(high), hex(low))
        output_bytes.append(sboxinv[16 * high + low])
        #print(output_bytes)
    return output_bytes

# Galois Multiplication
def galois(a, b):
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

# Shift rows for a 16 byte block of data
def shift_rows(block):
    row0 = block[0:13:4]        # Extract the rows from the array
    row1 = block[1:14:4]
    row2 = block[2:15:4]
    row3 = block[3:16:4]

    row1 = rotate_word(row1, 1) # Rotate to the left by one byte
    row2 = rotate_word(row2, 2) # Rotate by two bytes
    row3 = rotate_word(row3, 3) # Rotate by three bytes

    reassemble_block = []       # Reassemble the 1D array from the rows. Perhaps I should have done 2D arrays... :O
    for i in range(4):
        magic = [row0, row1, row2, row3]
        for j in magic:
            reassemble_block.append(j[i])
    return reassemble_block

# Inverse Shift rows for a 16 byte block of data
def shift_rowsinv(block):
    row0 = block[0:13:4]        # Extract the rows from the array
    row1 = block[1:14:4]
    row2 = block[2:15:4]
    row3 = block[3:16:4]

    row1 = rotate_word(row1, -1) # Rotate to the right by one byte
    row2 = rotate_word(row2, -2) # Rotate by two bytes
    row3 = rotate_word(row3, -3) # Rotate by three bytes

    reassemble_block = []      
    for i in range(4):
        magic = [row0, row1, row2, row3]
        for j in magic:
            reassemble_block.append(j[i])
    return reassemble_block

# Mix Columns for a 16 byte block of data
def mix_columns(block):
    output = []
    for i in range(0,16,4):
        output.append(galois(2, block[i]) ^ galois(3, block[i+1]) ^ galois(1, block[i+2]) ^ galois(1, block[i+3]))
        output.append(galois(1, block[i]) ^ galois(2, block[i+1]) ^ galois(3, block[i+2]) ^ galois(1, block[i+3]))
        output.append(galois(1, block[i]) ^ galois(1, block[i+1]) ^ galois(2, block[i+2]) ^ galois(3, block[i+3]))
        output.append(galois(3, block[i]) ^ galois(1, block[i+1]) ^ galois(1, block[i+2]) ^ galois(2, block[i+3]))
    return output

# Inverse Mix Columns for a 16 byte block of data
def mix_columnsinv(block):
    output = []
    for i in range(0,16,4):
        output.append(galois(14, block[i]) ^ galois(11, block[i+1]) ^ galois(13, block[i+2]) ^ galois(9, block[i+3]))
        output.append(galois(9, block[i]) ^ galois(14, block[i+1]) ^ galois(11, block[i+2]) ^ galois(13, block[i+3]))
        output.append(galois(13, block[i]) ^ galois(9, block[i+1]) ^ galois(14, block[i+2]) ^ galois(11, block[i+3]))
        output.append(galois(11, block[i]) ^ galois(13, block[i+1]) ^ galois(9, block[i+2]) ^ galois(14, block[i+3]))
    return output





# Create all round keys from the original cipher key. This expanded key table is 240 bytes in size for AES256. 16 bytes from the original key + 14 rounds of 16 bytes.
def expand_key():
    key = gen_key(PASSWORD)
    #allkeys = key[:16] 
    allkeys = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x9, 0xcf, 0x4f, 0x3c] # TEST DATA, REMOVE WHEN DONE AND UNCOMMENT ABOVE LINE
    for x in range(ROUNDS): # Repeat the process 14 times to create 14 round keys.
        index = x * 16 # Index to step through 16 bytes at a time
        ri = x * 4 # rcon index to step through 4 bytes at a time
        
        # 1st word (4 bytes) in the 16 byte block 
        t = allkeys[-4:]        # Temporary holds last 4 bytes of the list.
        t = rotate_word(t, 1) # Apply 1 step rotation to the four last values
        t = sub_word(t) # Subsitute the values in t with sbox substitution
        w1 = allkeys[0+index:4+index]
        w5 = [0] * 4  # Initialise an empty list of 4 bytes.
        for i in range(4):    # XOR the 1st word in the array with t and again with rcon, to create 5th word.
            w5[i] = w1[i] ^ t[i] ^ rcon[i+ri]
        allkeys.extend(w5) # Add the newly generated 5th word to the existing key array.

    
        # 2nd word in the 16 byte block
        w2 = allkeys[4+index:8+index]
        w6 = [0] * 4
        for i in range(4):
            w6[i] = w2[i] ^ w5[i] # XOR the list of 4 bytes
        allkeys.extend(w6) # Add the newly generated 6th word to the existing key array.
        
        
        # 3rd word in the 16 byte block
        w3 = allkeys[8+index:12+index]
        w7 = [0] * 4
        for i in range(4):
            w7[i] = w3[i] ^ w6[i]
        allkeys.extend(w7) # Add the newly generated 7th word to the existing key array.

        # 4th 4 bytes in the 16 byte block
        w4 = allkeys[12+index:16+index]
        w8 = [0] * 4
        for i in range(4):
            w8[i] = w4[i] ^ w7[i]
        allkeys.extend(w8) # Add the newly generated 8th word to the existing key array.

        # print('index: ', index)    
        # print('w1: ', w1)

        # print('rcon: ', rcon[0+ri:4+ri])
        # print('w2: ', w2)
        # print('w3: ', w3)
        # print('w4: ', w4)
        # print('w5: ', w5)
        # print('w6: ', w6)
        # print('w7: ', w7)
        # print('w8: ', w8)
    
    return allkeys
        

def encrypt(block):
    keyschedule = expand_key()
    cipher = []
    
    # AES pre-whitening round
    p0 = [0] * 16   # Initialise a 16 byte list to contain the 1st round encrypted data.
    for i in range(16):
        p0[i] = block[i] ^ keyschedule[i]   # XOR the input data with the original cipher key.
    cipher = p0

    

    # Additional rounds in the case of AES256
    for i in range(ROUNDS-1):   
        offset = i * 16 + 16    # Find the correct location for the key schedule
       
        # Substitute sbox phase
        p1 = sub_word(cipher)
        
        # Shift Rows phase
        p2 = shift_rows(p1)
        
        # Mix Columns phase
        p3 = mix_columns(p2)

        # XOR the input data with the Round generated key.
        p4 = [0] * 16   # Initialise a 16 byte list for the start of the next round.
        for i in range(16):
            p4[i] = p3[i] ^ keyschedule[i+offset]   
        cipher = p4     #   Make p4 the cipher for the new round.
    

    # Final round
    #
    # Substitute sbox phase
    cipher = sub_word(cipher)
    # Shift Rows phase
    cipher = shift_rows(cipher)

    p5 = [0] * 16   # Initialise a 16 byte list for the last XOR.
    for i in range(16):
        p5[i] = cipher[i] ^ keyschedule[ROUNDS * 16 + i]  
    return p5

def decrypt(block):
    keyschedule = expand_key()
    data = []

    # Cipher XOR'd with the final round key
    p0 = [0] * 16   # Initialise a 16 byte list to contain the 1st round encrypted data.
    for i in range(16):
        p0[i] = block[i] ^ keyschedule[ROUNDS * 16 + i]   # XOR the input data with the original cipher key.
    data = p0

    # Additional rounds in the case of AES256
    for i in reversed(range(ROUNDS-1)):   
        offset = i * 16 + 16    # Find the correct location for the key schedule
       
        # Shift Rows Inverse phase
        p1 = shift_rowsinv(data)
        
        # Substitute sbox Inverse
        p2 = sub_wordinv(p1)     
        
        # XOR the input data with the Round generated key.
        p3 = [0] * 16   # Initialise a 16 byte list for the start of the next round.
        for i in range(16):
            p3[i] = p2[i] ^ keyschedule[i+offset]   
        
        # Inverse Mix Columns phase
        p4 = mix_columnsinv(p3)
        data = p4     #   Make p4 the data for the new round.

    # Final round
    #
    # Invert Shift Rows phase
    data = shift_rowsinv(data)
    # Substitute sbox phase
    data = sub_wordinv(data)

    p5 = [0] * 16   # Initialise a 16 byte list for the last XOR.
    for i in range(16):
        p5[i] = data[i] ^ keyschedule[i]  
    return p5




# Main program execution


#read_file('data.dat')
TEST = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
CIPHER = [0x39, 0x25, 0x84, 0x1d, 0x2, 0xdc, 0x9, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0xb, 0x32]

a = encrypt(TEST)
if a == CIPHER:
    print("Encryption works!")
b = decrypt(CIPHER)
if b == TEST:
    print("Decryption works!")



