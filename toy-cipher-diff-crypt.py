import sys
import random

"""
This script was written for the Differential Cryptanalysis Tutorial

https://maticstric.github.io/differential-cryptanalysis-tutorial/
"""

""" --- Feel free to edit the variables below --- """

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]

KEY1 = 0xb
KEY2 = 0xd

""" --------------------------------------------- """


def main():
    validate_input()

    diff_dist_table = build_difference_distribution_table(SBOX)
    diff_dist_table_string = get_diff_dist_table_string(diff_dist_table)

    print('\nDifference distribution table:')
    print(diff_dist_table_string) 

    good_pair = None

    # It's possible that no good pair exists for a certain diff char
    # In that case, we have to keep trying different diff chars
    while good_pair == None:
        diff_char = pick_random_differential_characteristic(diff_dist_table)

        good_pair = get_good_pair(diff_char)

    print('\nFound differential characteristic and a corresponding good pair:')
    print(f'Differential characteristic: {hex(diff_char[0])} -> {hex(diff_char[1])}')
    print(f'Good pair: {hex(good_pair[0])} and {hex(good_pair[1])}')

    possible_key_pairs = get_possible_key_pairs(good_pair, diff_dist_table)

    print('\nFound the following possible key pairs:')
    for k1, k2 in possible_key_pairs:
        print(f'KEY1 = {hex(k1)}    KEY2 = {hex(k2)}')

    print('\nChecking all possible key pairs...') 

    key1, key2 = confirm_key_guesses(possible_key_pairs)

    print('\nFound correct round keys!') 

    print('**************')
    print('  KEY1 = ' + hex(key1))
    print('  KEY2 = ' + hex(key2))
    print('**************')

    if key1 != KEY1 or key2 != KEY2:
        print('Depending on the SBOX, note that it is possible for two separate key pairs to be equally valid (i.e. they encrypt the same plaintexts to the same ciphertexts).')



""" --- Differential Cryptanalysis --- """

def confirm_key_guesses(possible_key_pairs):
    """
    Given all possible key pairs, checks which one encrypts plaintexts to the
    correct ciphertexts. Returnes the final key guesses in this form:

    (key1_guess, key2_guess)
    """

    for key1_guess, key2_guess in possible_key_pairs:

        correct = True

        # See if any plaintext (0-15) doesn't encrypt correctly with key guess
        for plaintext in range(16):
            encryption_guess = encrypt(plaintext, key1_guess, key2_guess, SBOX)
            encryption_correct = encrypt(plaintext, KEY1, KEY2, SBOX)

            if encryption_guess != encryption_correct:
                correct = False
                break

        # Found correct keys!
        if correct:
            return (key1_guess, key2_guess)

def get_possible_key_pairs(good_pair, diff_dist_table):
    """
    Using the XOR logic explained in the tutorial, get all possible key
    pairs for a given good pair and difference distribution table.

    Returns a list of 2-tuples in this form:
    
    (key1_guess, key2_guess)
    """

    possible_key_pairs = []

    plain1 = good_pair[0]
    plain2 = good_pair[1]
    cipher1 = good_pair[2]
    cipher2 = good_pair[3]

    input_xor = plain1 ^ plain2
    output_xor = cipher1 ^ cipher2

    # Remember that each entry is a list of 4-tuples (x, x_star, y, y_star)
    # Look at build_difference_distribution_table function.
    # This makes it easy to break the keys now
    diff_dist_entry = diff_dist_table[input_xor][output_xor]

    for entry in diff_dist_entry:
        x = entry[0]
        x_star = entry[1]
        y = entry[2]
        y_star = entry[3]

        # plain1 ^ x is equal to plain2 ^ x_star, so we can pick either
        key1_guess = plain1 ^ x

        # cipher1 ^ y is equal to cipher2 ^ y_star, so we can pick either
        key2_guess = cipher1 ^ y

        possible_key_pairs.append((key1_guess, key2_guess))

    return possible_key_pairs

def get_good_pair(diff_char):
    """
    This function finds a pair of plaintexts whose XOR is equal to the input
    XOR in diff_char and whose corresponding ciphertext XOR is equal to the
    output XOR in diff_char. It returns it in this form:

    (plaintext1, plaintext2, ciphertext1, ciphertext2)
    """

    input_xor = diff_char[0]
    output_xor = diff_char[1]

    # Try every possible pair of plaintexts which XOR to input_xor
    for plain1 in range(16):
        plain2 = plain1 ^ input_xor # plain1 and plain2 now XOR to input_xor

        # Get the ciphertexts for plain1 and plain2. Remember that differential
        # cryptanalysis is a chosen plaintext attack, so we can do this
        cipher1 = encrypt(plain1, KEY1, KEY2, SBOX)
        cipher2 = encrypt(plain2, KEY1, KEY2, SBOX)

        if cipher1 ^ cipher2 == output_xor: # Good pair found!
            return (plain1, plain2, cipher1, cipher2)

    # If here, no good pair was found for the given diff_char
    return None

def pick_random_differential_characteristic(diff_dist_table):
    """
    This function returns a non-zero differential characteristic in the
    difference distribution table in this form:

    (input_xor, output_xor)
    """

    diff_char = None

    while diff_char == None:
        input_xor, output_xor = random.randint(0, 15), random.randint(0, 15)

        # The 0, 0 entry in the diff dist table is always 16. Ignore it
        if input_xor == 0 and output_xor == 0: continue

        # Pick any other non-zero entry
        if len(diff_dist_table[input_xor][output_xor]) != 0:
            diff_char = (input_xor, output_xor)

    return diff_char

def build_difference_distribution_table(sbox):
    """
    Instead of each entry only including the number of appearances of the
    output XOR given the input XOR, it includes a list of 4-tuples which are
    in this order:

    (x, x_star, y, y_star).

    This makes it easier to break the keys later.

    In other words, you can get the pure difference distribution table by
    the length of the list at each entry:

    len(diff_dist_table[input_xor][output_xor])

    You can print it with the get_diff_dist_table_string function
    """

    diff_dist_table = [[[] for i in range(16)] for j in range(16)]

    for x_prime in range(16):
        for x in range(16):
            x_star = x ^ x_prime

            y = sbox[x]
            y_star = sbox[x_star]
            y_prime = y ^ y_star

            diff_dist_table[x_prime][y_prime].append((x, x_star, y, y_star))

    return diff_dist_table



""" Toy Cipher Implementation """

def encrypt(state, key1, key2, sbox):
    state = add_round_key(state, key1)
    state = sub(state, sbox)
    state = add_round_key(state, key2)

    return state

def decrypt(state, key1, key2, sbox):
    # For decryption we need the inverse sbox
    inv_sbox = calculate_inv_sbox(sbox)

    state = add_round_key(state, key2)
    state = sub(state, inv_sbox)
    state = add_round_key(state, key1)

    return state

def sub(state, sbox):
    return sbox[state]

def add_round_key(state, key):
    return state ^ key



""" Misc Functions """

def validate_input():
    if len(SBOX) != 16:
        sys.exit('Error: SBOX list should have 16 elements')

    for i in range(len(SBOX)):
        if i not in SBOX:
            sys.exit('Error: SBOX list doesn\'t contain ' + str(hex(i)) + '. SBOX list elements should contain all values between 0 and 0xf, with no duplicates')


    if KEY1 < 0 or KEY1 > 0xf:
        sys.exit('Error: KEY1 should be a value between 0 and 0xf')

    if KEY2 < 0 or KEY2 > 0xf:
        sys.exit('Error: KEY2 should be a value between 0 and 0xf')

def calculate_inv_sbox(SBOX):
    inv_sbox = [0] * 16

    for i, val in enumerate(SBOX):
        inv_sbox[val] = i 

    return inv_sbox

def get_diff_dist_table_string(diff_dist_table):
    string =  '+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+\n'
    string += '|   | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |\n'
    string += '+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+\n'

    for input_xor in range(16):
        string += f'| {input_xor:x} |'

        for output_xor in range(16):
            appearances = len(diff_dist_table[input_xor][output_xor])

            if appearances > 9: # Two digits make everything look weird
                string += f' {appearances}|'
            else:
                string += f' {appearances} |'


        string += '\n+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+\n'

    # Remove last newline
    string = string[:-1]

    return string



if __name__=="__main__":
    main()
