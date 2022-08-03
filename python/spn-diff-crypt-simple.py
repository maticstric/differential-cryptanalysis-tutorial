import sys
import random
import time
import math

"""
This script was written for the Differential Cryptanalysis Tutorial.
https://maticstric.github.io/differential-cryptanalysis-tutorial/

Based on "Cryptography: Theory and Practice" by Douglas R. Stinson """

""" --- Feel free to edit the variables below --- """

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]

PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf] 

KEY1 = 0x1a6d
KEY2 = 0x2ac2
KEY3 = 0x452f
KEY4 = 0x6ff1
KEY5 = 0xb520

# Constant for choosing number of plaintexts.
# num_of_plaintexts = C / trail_probability
C = 30

""" --------------------------------------------- """

INV_SBOX = [SBOX.index(i) if i in SBOX else i for i in range(len(SBOX))]
INV_PBOX = [PBOX.index(i) if i in PBOX else i for i in range(len(PBOX))]

def main():
    validate_input()

    diff_dist_table = build_difference_distribution_table(SBOX)
    diff_dist_table_string = get_diff_dist_table_string(diff_dist_table)

    print('\nDifference distribution table:')
    print(diff_dist_table_string) 

    print('\nFinding most probable differential trails for all rounds... ', end='', flush=True)
    # Get differential trails for all rounds
    most_probable_diff_trails_3 = find_highly_probable_differential_trails(diff_dist_table, 3)
    most_probable_diff_trails_2 = find_highly_probable_differential_trails(diff_dist_table, 2)
    most_probable_diff_trails_1 = find_highly_probable_differential_trails(diff_dist_table, 1)
    most_probable_diff_trails_0 = find_highly_probable_differential_trails(diff_dist_table, 0)
    print('FOUND')

    print('\nFinding good combinations of differential trails which will break each round key...')
    # Find good combinations of diff trails which will break each full round key
    useful_diff_trails_3 = find_differential_trails_to_break_full_key(3, most_probable_diff_trails_3)
    useful_diff_trails_2 = find_differential_trails_to_break_full_key(2, most_probable_diff_trails_2)
    useful_diff_trails_1 = find_differential_trails_to_break_full_key(1, most_probable_diff_trails_1)
    useful_diff_trails_0 = find_differential_trails_to_break_full_key(0, most_probable_diff_trails_0)

    print(f'\n--- KEY5 Trails ---')
    for dt in useful_diff_trails_3: print(f'{format(dt[2], "#06x")} -> {format(dt[3], "#06x")} (probability {dt[1]})')
    print(f'\n--- KEY4 Trails ---')
    for dt in useful_diff_trails_2: print(f'{format(dt[2], "#06x")} -> {format(dt[3], "#06x")} (probability {dt[1]})')
    print(f'\n--- KEY3 Trails ---')
    for dt in useful_diff_trails_1: print(f'{format(dt[2], "#06x")} -> {format(dt[3], "#06x")} (probability {dt[1]})')
    print(f'\n--- KEY2 Trails ---')
    for dt in useful_diff_trails_0: print(f'{format(dt[2], "#06x")} -> {format(dt[3], "#06x")} (probability {dt[1]})')

    # We'll be building up this arrray of round keys
    round_keys = [0, 0, 0, 0, 0]

    start = time.time()

    print('\n----------------------------')

    print('\nBreaking KEY5...')
    round_keys[4] = break_round_key(3, useful_diff_trails_3, round_keys)
    print('KEY5 = ' + format(round_keys[4], '#06x'))

    print('\nBreaking KEY4...')
    round_keys[3] = break_round_key(2, useful_diff_trails_2, round_keys)
    print('KEY4 = ' + format(round_keys[3], '#06x'))

    print('\nBreaking KEY3...')
    round_keys[2] = break_round_key(1, useful_diff_trails_1, round_keys)
    print('KEY3 = ' + format(round_keys[2], '#06x'))

    print('\nBreaking KEY2...')
    round_keys[1] = break_round_key(0, useful_diff_trails_0, round_keys)
    print('KEY2 = ' + format(round_keys[1], '#06x'))

    print('\nBreaking KEY1...')
    round_keys[0] = break_first_round_key(round_keys)
    print('KEY1 = ' + format(round_keys[0], '#06x'))

    end = time.time()

    print('\nFound correct round keys in ' + str(round(end - start, 2)) + ' seconds!') 

    print('*****************')
    for i in range(len(round_keys)):
        print('  KEY' + str(i + 1) + ' = ' + format(round_keys[i], '#06x'))
    print('*****************')



""" --- DIFFERENTIAL CRYPTANALYSIS --- """

def break_round_key(round_num, useful_diff_trails, round_keys):
    """
    Breaks a whole round key given some useful differential trails by choosing
    ones which will break keybits we have not yet broken until all key bits
    are broken.

    Returns the most probable round keys in the order of their probability.
    """

    total_key_bits_broken = 0
    partial_keys_to_combine = []

    for useful_diff_trail in useful_diff_trails:
        probability = useful_diff_trail[1]
        input_xor = useful_diff_trail[2]
        output_xor = useful_diff_trail[3]

        breaking_key_bits = find_which_key_bits_will_be_broken(round_num, output_xor)
        broken_key_bits = break_key_bits(round_num, probability, input_xor, output_xor, breaking_key_bits, round_keys)

        # broken_key_bits now the most likely partial key. At the end of the
        # while loop, we'll combine it into the full key

        # If we got some key bits which have already been broken by a previous
        # trail, ignore those key bits so we don't overwrite them
        broken_key_bits = broken_key_bits & (~total_key_bits_broken & 0xffff)

        total_key_bits_broken |= breaking_key_bits

        partial_keys_to_combine.append(broken_key_bits)

    round_key = combine_partial_keys(partial_keys_to_combine)

    return round_key

def combine_partial_keys(partial_keys_to_combine):
    """
    Given a list of partial keys this function combines them into
    a full round key.
    """

    full_key = 0

    for partial_key in partial_keys_to_combine:
        full_key |= partial_key

    return full_key

def break_key_bits(round_num, probability, input_xor, output_xor, breaking_key_bits, round_keys):
    """
    Breaks bits of the round key specified by the breaking_key_bits array by
    generating random plaintexts (i.e. gets a partial key).

    Returns the most probable keybits for the specified bits.
    """

    key_count_dict = {}

    # We need some number of randomly chosen plaintexts. The simplest function
    # for choosing this number is to divide some constant by the probability
    # of the trail. The higher the probability, the fewer plaintexts are needed.

    num_chosen_plaintexts = round(C / probability)

    for i in range(num_chosen_plaintexts):
        text1 = choose_random_plaintext()
        text2 = text1 ^ input_xor

        # Now, text1 ^ text2 = input_xor and we can encrypt both

        text1 = encrypt(text1, KEY1, KEY2, KEY3, KEY4, KEY5)
        text2 = encrypt(text2, KEY1, KEY2, KEY3, KEY4, KEY5)

        # This will modify the key_count_dict after key guesses
        guess_key_bits(round_num, text1, text2, output_xor, key_count_dict, breaking_key_bits, round_keys)

    # Extract the most likely key out of the dictonary
    if len(key_count_dict) == 0:
        sys.exit('Error: Unable to find key. Run again or attempt to increase C value.')
        
    most_probable_key = sorted(key_count_dict.items(), key=lambda x: x[1], reverse=True)[0][0]
    most_probable_key = int(most_probable_key, 16)

    return most_probable_key

def guess_key_bits(round_num, ciphertext1, ciphertext2, output_xor, key_count_dict, breaking_key_bits, round_keys):
    """
    For a given ciphertext pair, this function goes through every possible key
    bit combination (specified by breaking_key_bits). It returns nothing.
    Instead, it increments the values in key_count_dict whenever the highly-
    likely output XOR matches the XOR of the partially decrypted ciphertexts.
    """

    total_needed_key_guesses = int(math.pow(2, count_one_bits(breaking_key_bits)))

    for i in range(total_needed_key_guesses):
        key_guess_bits = 0

        div = total_needed_key_guesses / 2

        # This for loop is hard to understand but, as the outer for loop is
        # looping, it will loop thorough all possible keys only for the bits
        # where breaking_key_bits is set
        for j in range(16):
            if get_bit(breaking_key_bits, j) == 1:
                if i > div - 1 and i % (div * 2) >= div:
                    key_guess_bits = set_bit(key_guess_bits, j, 1)

                div /= 2

        # Set round key so partial_decryption will use it
        round_keys[round_num + 1] = key_guess_bits

        partial_xor = partial_decryption(round_num, ciphertext1, ciphertext2, round_keys)

        # Make the dictionary keys a string so it's easier to debug
        key_as_string = format(key_guess_bits, '#06x')

        # If the XORs match, increment value in dictionary 
        if partial_xor == output_xor:
            if key_as_string not in key_count_dict:
                key_count_dict[key_as_string] = 1
            else:
                key_count_dict[key_as_string] += 1

def break_first_round_key(round_keys):
    """
    For the first key, we don't need anything special. Just decrypt a random
    encrypted plaintext all the way to the key with the keys we've already
    broken and then XOR that value with the original plaintext.
    """

    # Encrypt random plaintext
    plaintext = choose_random_plaintext()
    ciphertext = encrypt(plaintext, KEY1, KEY2, KEY3, KEY4, KEY5)

    # Decrypt ciphertext all the way to last xor with the round_keys we found
    ciphertext = add_round_key(ciphertext, round_keys[4])
    ciphertext = substitute(ciphertext, INV_SBOX)

    ciphertext = add_round_key(ciphertext, round_keys[3])
    ciphertext = permutate(ciphertext, INV_PBOX)
    ciphertext = substitute(ciphertext, INV_SBOX)

    ciphertext = add_round_key(ciphertext, round_keys[2])
    ciphertext = permutate(ciphertext, INV_PBOX)
    ciphertext = substitute(ciphertext, INV_SBOX)

    ciphertext = add_round_key(ciphertext, round_keys[1])
    ciphertext = permutate(ciphertext, INV_PBOX)
    ciphertext = substitute(ciphertext, INV_SBOX)

    # Get the last key
    return plaintext ^ ciphertext

def partial_decryption(round_num, ciphertext1, ciphertext2, round_keys):
    """
    This function partially decrypts ciphertext1 and ciphertext2 using
    round_keys up to round_num. It returns their XOR after partial decryption.
    """

    for i in range(4, round_num, -1):
        ciphertext1 = add_round_key(ciphertext1, round_keys[i])
        ciphertext2 = add_round_key(ciphertext2, round_keys[i])

        if i < 4:
            ciphertext1 = permutate(ciphertext1, INV_PBOX)
            ciphertext2 = permutate(ciphertext2, INV_PBOX)

        ciphertext1 = substitute(ciphertext1, INV_SBOX)
        ciphertext2 = substitute(ciphertext2, INV_SBOX)

    partial_xor = ciphertext1 ^ ciphertext2
        
    return partial_xor

def find_which_key_bits_will_be_broken(round_num, output_xor):
    """
    In order to guess key bits we need to know which bits to guess. This
    function returns a bit string with 1 bits representing bits which we're
    attempting to break given the output_xor and round_num.
    """

    breaking_key_bits = 0

    for i in range(4):
        if get_nibble(output_xor, i) != 0:
            breaking_key_bits = set_nibble(breaking_key_bits, i, 0xf)

    if round_num < 3: # If round_num < 3 we need to take the permutation into account
        breaking_key_bits = permutate(breaking_key_bits, PBOX)
        
    return breaking_key_bits

def find_differential_trails_to_break_full_key(round_num, most_probable_diff_trails):
    """
    Uses the find_useful_diff_trail function to find a combination of useful
    diff trails which together break the full key.
    """

    useful_diff_trails = []
    sboxes_already_used = [False, False, False, False]

    while not all(sboxes_already_used):
        useful_diff_trail = find_useful_diff_trail(round_num, most_probable_diff_trails, sboxes_already_used)

        output_xor = useful_diff_trail[3]

        # Mark which sboxes this used up
        for i in range(4):
            if get_nibble(output_xor, i) != 0:
                sboxes_already_used[i] = True

        useful_diff_trails.append(useful_diff_trail)

    return useful_diff_trails

def find_useful_diff_trail(round_num, most_probable_diff_trails, sboxes_already_used):
    """
    We should only use a differtial trail if it breaks key bits which we
    haven't broken before. This function finds such a differential trail.
    """

    for diff_trail in most_probable_diff_trails:
        output_xor = diff_trail[3]

        # Check if this diff_trail will use any sboxes which we haven't used already
        for i in range(4):
            if get_nibble(output_xor, i) != 0 and sboxes_already_used[i] == False: # Hit! We can use this one
                return diff_trail

def find_highly_probable_differential_trails(diff_dist_table, round_num):
    """
    Finds a highly probable differential trails for every possible input XOR,
    with the help of the find_differential_trail function.

    Returns a list of differential trails in this form:

    (preference, probability, input_xor, output_xor)
    """

    differential_trails = []

    for i in range(16):
        for j in range(16):
            for k in range(16):
                for l in range(16):

                    if i == 0 and j == 0 and k == 0 and l == 0: continue # We don't care about all zero xors

                    input_xor = 0

                    input_xor = set_nibble(input_xor, 0, l)
                    input_xor = set_nibble(input_xor, 1, k)
                    input_xor = set_nibble(input_xor, 2, j)
                    input_xor = set_nibble(input_xor, 3, i)

                    output_xor, probability, preference = find_differential_trail(input_xor, diff_dist_table, round_num)

                    differential_trails.append((preference, probability, input_xor, output_xor))

    differential_trails.sort(reverse=True)

    return differential_trails

def find_differential_trail(input_xor, diff_dist_table, round_num):
    """
    Greedily finds a highly probable differential trail of length round_num
    with a certain input XOR. Note that because it's greedy (always takes the
    most likely SBOX output XOR) it's not necessarily the most probable.

    Returns the final XOR, the trail's raw probability, and its "preference"
    which depends on the final number of active SBOXes in this form:

    (final_xor, probability, preference)
    """

    probability = 1

    current_xor = input_xor

    for r in range(round_num):
        # XOR doesn't change over key addition, so we can just ignore it

        # XOR going through sbox changes the probability (non-linear)
        for i in range(4):
            if get_nibble(current_xor, i) > 0: # SBOX is active

                # Get max entry in diff_dist row and adjust probability based on that
                max_count = max(diff_dist_table[get_nibble(current_xor, i)])
                most_probable_output_xor = diff_dist_table[get_nibble(current_xor, i)].index(max_count)

                probability *= max_count / 16

                current_xor = set_nibble(current_xor, i, most_probable_output_xor)

        # XOR changes over permutation, but the probability is not affected (linear)
        current_xor = permutate(current_xor, PBOX)


    # If we get a highly probable trail which has all the final SBOXes active,
    # we'll have to break a whole round key at once. It's much better to find
    # a trail with few final SBOXes active so we can break smaller portions of
    # the round key at a time. This is why we assign a "preference" to each
    # trail which is a function of the trail's probability and its number of
    # final active SBOXes.

    num_final_active_sboxes = 0
    
    for i in range(4):
        if get_nibble(current_xor, i) > 0:
            num_final_active_sboxes += 1

    preference = probability

    # 1 active SBOX: perfect
    # 2 active SBOXes: the key bits are broken within a couple of seconds. We 
    #                  won't adjust preference since it's fast enough and only
    #                  1 active SBOX is not likely anyway
    # 3 active SBOXes: could take longer sec so divide preference by some
    #                  constant to discourage using it.
    # 4 active SBOXes: will take a very long time so we never want to use them. 
    #                  We set preference to zero so we'll try to find 
    #                  alternatives with fewer active sboxes

    if num_final_active_sboxes == 3: preference /= 4
    if num_final_active_sboxes == 4: preference = 0

    return (current_xor, probability, preference)

def build_difference_distribution_table(sbox):
    diff_dist_table = [[0 for i in range(len(sbox))] for j in range(len(sbox))]

    for x_prime in range(16):
        for x in range(16):
            x_star = x ^ x_prime
            y_prime = sbox[x] ^ sbox[x_star]

            diff_dist_table[x_prime][y_prime] += 1

    return diff_dist_table

def choose_random_plaintext():
    return random.randint(0, 0xffff)



""" --- SPN CIPHER IMPLEMENTATION --- """

def encrypt(state, key1, key2, key3, key4, key5):
    state = add_round_key(state, key1)
    state = substitute(state, SBOX)
    state = permutate(state, PBOX)

    state = add_round_key(state, key2)
    state = substitute(state, SBOX)
    state = permutate(state, PBOX)

    state = add_round_key(state, key3)
    state = substitute(state, SBOX)
    state = permutate(state, PBOX)

    state = add_round_key(state, key4)
    state = substitute(state, SBOX)

    state = add_round_key(state, key5)

    return state

def decrypt(state, key1, key2, key3, key4, key5):
    state = add_round_key(state, key5)

    state = substitute(state, INV_SBOX)
    state = add_round_key(state, key4)

    state = permutate(state, INV_PBOX)
    state = substitute(state, INV_SBOX)
    state = add_round_key(state, key3)

    state = permutate(state, INV_PBOX)
    state = substitute(state, INV_SBOX)
    state = add_round_key(state, key2)

    state = permutate(state, INV_PBOX)
    state = substitute(state, INV_SBOX)
    state = add_round_key(state, key1)

    return state

def add_round_key(state, key):
    state ^= key

    return state

def substitute(state, sbox):
    new_state = 0

    for i in range(4):
        new_state = set_nibble(new_state, i, sbox[get_nibble(state, i)])

    return new_state

def permutate(state, pbox):
    new_state = 0

    for i in range(16):
        new_state = set_bit(new_state, i, get_bit(state, pbox[i]))

    return new_state



""" --- BIT STRING FUNCTIONS --- """

def count_one_bits(bit_string):
    """
    Returns the number of 1 bits in bit_string
    """

    count = 0

    while bit_string > 0:
        if bit_string & 1 == 1: count += 1

        bit_string >>= 1

    return count

def get_bit(bit_string, index):
    """
    Returns the index-th bit in bit_string

    Zero indexed and index zero is the least significant bit
    """

    mask = 0x1 << index
    nibble = bit_string & mask
    nibble = nibble >> index

    return nibble

def set_bit(bit_string, index, value):
    """
    Sets the index-th bit in bit_string. Returns the new bit string

    Value should be either 0 or 1. Otherwise returns None

    Zero indexed and index zero is the least significant bit
    """

    if value != 0 and value != 1:
        return None

    mask = 0x1 << index
    bit_string &= ~mask
    bit_string ^= (value << index)

    return bit_string

def get_nibble(bit_string, index):
    """
    Returns the index-th nibble int bit_string

    Zero indexed and index zero is the least significant bit
    """

    index *= 4

    mask = 0xf << index
    nibble = bit_string & mask
    nibble = nibble >> index

    return nibble

def set_nibble(bit_string, index, value):
    """
    Sets the index-th nibble in bit_string. Returns the new bit string

    Value should be a number between 0 and 0xf. Otherwise returns None

    Zero indexed and index zero is the least significant bit
    """

    if value < 0 or value > 0xf:
        return None

    index *= 4

    mask = 0xf << index
    bit_string &= ~mask
    bit_string ^= (value << index)

    return bit_string



""" --- MISC FUNCTIONS --- """

def validate_input():
    if len(SBOX) != 16:
        sys.exit('Error: SBOX list should have 16 elements')

    if len(PBOX) != 16:
        sys.exit('Error: PBOX list should have 16 elements')

    for i in range(len(SBOX)):
        if i not in SBOX:
            sys.exit('Error: SBOX list doesn\'t contain ' + str(hex(i)) + '. SBOX list elements should contain all values between 0 and 0xf, with no duplicates')

    for i in range(len(PBOX)):
        if i not in PBOX:
            sys.exit('Error: PBOX list doesn\'t contain ' + str(hex(i)) + '. PBOX list elements should contain all values between 0 and 0xf, with no duplicates')

    if KEY1 < 0 or KEY1 > 0xffff:
        sys.exit('Error: KEY1 should be a value between 0 and 0xffff')

    if KEY2 < 0 or KEY2 > 0xffff:
        sys.exit('Error: KEY2 should be a value between 0 and 0xffff')

    if KEY3 < 0 or KEY3 > 0xffff:
        sys.exit('Error: KEY3 should be a value between 0 and 0xffff')

    if KEY4 < 0 or KEY4 > 0xffff:
        sys.exit('Error: KEY4 should be a value between 0 and 0xffff')

    if KEY5 < 0 or KEY5 > 0xffff:
        sys.exit('Error: KEY5 should be a value between 0 and 0xffff')

def get_diff_dist_table_string(diff_dist_table):
    string =  '+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+\n'
    string += '|   | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | b | c | d | e | f |\n'
    string += '+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+\n'

    for input_xor in range(16):
        string += f'| {input_xor:x} |'

        for output_xor in range(16):
            appearances = diff_dist_table[input_xor][output_xor]

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
