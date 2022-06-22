import sys
import random
import time
import math

from BitString import BitString

"""
This script was written for the Differential Cryptanalysis Tutorial.
https://maticstric.github.io/differential-cryptanalysis-tutorial/

Based on "Cryptography: Theory and Practice" by Douglas R. Stinson
"""

""" --- Feel free to edit the variables below --- """

SBOX = [0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7]

PBOX = [0x0, 0x4, 0x8, 0xc, 0x1, 0x5, 0x9, 0xd, 0x2, 0x6, 0xa, 0xe, 0x3, 0x7, 0xb, 0xf]

KEY1 = BitString(0x1a6d)
KEY2 = BitString(0x2ac2)
KEY3 = BitString(0x452f)
KEY4 = BitString(0x6ff1)
KEY5 = BitString(0xb520)

NUM_CHOSEN_PLAINTEXTS = 1000

""" --------------------------------------------- """

INV_SBOX = [SBOX.index(i) if i in SBOX else i for i in range(len(SBOX))]
INV_PBOX = [PBOX.index(i) if i in PBOX else i for i in range(len(PBOX))]



def main():
    random.seed(0)
    validate_input()

    diff_dist_table = build_difference_distribution_table(SBOX)
    diff_dist_table_string = get_diff_dist_table_string(diff_dist_table)

    print('\nDifference distribution table:')
    print(diff_dist_table_string) 

    # The vast majority of trails will have very low probabilities, so we only
    # care about the first trails in the list. Here, we just take to first 100
    num_of_trails = 100

    round_keys = [BitString(0), BitString(0), BitString(0), BitString(0), BitString(0)]

    for round_num in range(3, -1, -1):
        most_probable_diff_trails = find_highly_probable_differential_trails(diff_dist_table, round_num)[:num_of_trails]
        round_keys[round_num + 1] = break_round_key(round_num, most_probable_diff_trails, round_keys)
        print(round_keys[round_num + 1])


""" --- DIFFERENTIAL CRYPTANALYSIS --- """

def break_round_key(round_num, most_probable_diff_trails, round_keys):
    round_key = BitString(0) # We'll be building this round key
    sboxes_already_used = [False, False, False, False]

    while not all(sboxes_already_used):
        useful_diff_trail = find_useful_diff_trail(round_num, most_probable_diff_trails, sboxes_already_used)

        input_xor = useful_diff_trail[1]
        output_xor = useful_diff_trail[2]

        breaking_key_bits = find_which_key_bits_will_be_broken(round_num, output_xor)
        #print(bin(breaking_key_bits.bit_string))
        broken_key_bits = break_key_bits(round_num, input_xor, output_xor, breaking_key_bits, round_keys)

        # Set the keybits which were broken
        for i in range(16):
            if breaking_key_bits.get_bit(i) == 1:
                round_key.set_bit(i, broken_key_bits.get_bit(i))

        # Mark which sboxes this used up
        for i in range(4):
            if output_xor.get_nibble(i) != 0:
                sboxes_already_used[i] = True

    return round_key

def break_key_bits(round_num, input_xor, output_xor, breaking_key_bits, round_keys):
    key_count_dict = {}

    # We need some number of randomly chosen plaintexts. This number is pulled
    # out of thin air. It seems to work well, and is still fairly quick.
    # A better way would be to create a function which chooses this number
    # based on the probability of the trail.
    for i in range(NUM_CHOSEN_PLAINTEXTS):
        text1 = choose_random_plaintext()
        text2 = BitString(text1.bit_string ^ input_xor.bit_string)
        #print(text1)
        #print(text2)
        #print(hex(text1.bit_string ^ text2.bit_string))

        # Now, text1 ^ text2 = input_xor and we can encrypt both

        encrypt(text1, KEY1, KEY2, KEY3, KEY4, KEY5)
        encrypt(text2, KEY1, KEY2, KEY3, KEY4, KEY5)

        #print(text1)
        #print(text2)

        # This will modify the key_count_dict after key guesses
        guess_key_bits(round_num, text1, text2, output_xor, key_count_dict, breaking_key_bits, round_keys)

    #print(key_count_dict)
    # Extract the most likely key out of the dictonary
    most_probable_key = sorted(key_count_dict.items(), key=lambda x: x[1], reverse=True)[0][0]
    most_probable_key = BitString(int(most_probable_key, 16))

    return most_probable_key

def guess_key_bits(round_num, ciphertext1, ciphertext2, output_xor, key_count_dict, breaking_key_bits, round_keys):
    """
    For a given ciphertext pair, this function goes through every possible key
    bit combination (specified by breaking_key_bits). It returns nothing.
    Instead, it increments the values in key_count_dict whenever the highly-
    likely output XOR matches the XOR of the partially decrypted ciphertexts.
    """

    total_needed_key_guesses = int(math.pow(2, breaking_key_bits.count_one_bits()))

    for i in range(total_needed_key_guesses):
        key_guess_bits = BitString(0)

        div = total_needed_key_guesses / 2

        # This for loop is hard to understand but, as the outer for loop is
        # looping, it will loop thorough all possible keys only for the bits
        # where breaking_key_bits is set
        for j in range(16):
            if breaking_key_bits.get_bit(j) == 1:
                if i > div - 1 and i % (div * 2) >= div:
                    key_guess_bits.set_bit(j, 1)

                div /= 2

        # Set round key so partial_decryption will use it
        round_keys[round_num + 1] = key_guess_bits

        # partial_decryption will overwrite these so make a copy
        _ct1 = BitString(ciphertext1.bit_string)
        _ct2 = BitString(ciphertext2.bit_string)

        partial_xor = partial_decryption(round_num, _ct1, _ct2, round_keys)
        #print(partial_xor)
        #print('---')

        # Make the dictionary keys a string so it's easier to debug
        key_as_string = format(key_guess_bits.bit_string, '#06x')

        # If the XORs match, increment value in dictionary 
        if partial_xor.bit_string == output_xor.bit_string:
            if key_as_string not in key_count_dict:
                key_count_dict[key_as_string] = 1
            else:
                key_count_dict[key_as_string] += 1

def partial_decryption(round_num, ciphertext1, ciphertext2, round_keys):
    """
    This function partially decrypts ciphertext1 and ciphertext2 using
    round_keys up to round_num. It returns their XOR after partial decryption.
    """
    #print('---')
    #print(ciphertext1)

    for i in range(4, round_num, -1):
        add_round_key(ciphertext1, round_keys[i])
        add_round_key(ciphertext2, round_keys[i])
        #print(ciphertext1)

        if i < 4:
            permutate(ciphertext1, INV_PBOX)
            permutate(ciphertext2, INV_PBOX)
            #print('p')
            #print(ciphertext1)

        substitute(ciphertext1, INV_SBOX)
        substitute(ciphertext2, INV_SBOX)
        #print(ciphertext1)

    #print(ciphertext1)
    partial_xor = BitString(ciphertext1.bit_string ^ ciphertext2.bit_string)
        
    return partial_xor

def find_which_key_bits_will_be_broken(round_num, output_xor):
    """
    In order to guess key bits we need to know which bits to guess. This
    function returns a BitString with 1 bits representing bits which we're
    attempting to break given the output_xor and round_num.
    """

    breaking_key_bits = BitString(0)

    if output_xor.get_nibble(0) != 0: breaking_key_bits.set_nibble(0, 0xf)
    if output_xor.get_nibble(1) != 0: breaking_key_bits.set_nibble(1, 0xf)
    if output_xor.get_nibble(2) != 0: breaking_key_bits.set_nibble(2, 0xf)
    if output_xor.get_nibble(3) != 0: breaking_key_bits.set_nibble(3, 0xf)

    if round_num < 3: # If round_num < 3 we need to take the permutation into account
        permutate(breaking_key_bits, INV_PBOX)
        
    return breaking_key_bits

def find_useful_diff_trail(round_num, most_probable_diff_trails, sboxes_already_used):
    """
    We should only use a differtial trail if it breaks key bits which we
    haven't broken before. This function finds such a differential trail.
    """

    for diff_trail in most_probable_diff_trails:
        output_xor = diff_trail[2]

        # Check if this diff_trail will use any sboxes which we haven't used already
        for i in range(len(sboxes_already_used)):
            if output_xor.get_nibble(i) != 0 and sboxes_already_used[i] == False: # Hit! We can use this one
                return diff_trail

def find_highly_probable_differential_trails(diff_dist_table, round_num):
    """
    Finds a highly probable differential trails for every possible input XOR,
    with the help of the find_differential_trail function.

    Returns a list of differential trails in this form:

    (preference, input_xor, output_xor)
    """

    differential_trails = []

    for i in range(16):
        for j in range(16):
            for k in range(16):
                for l in range(16):
                    if i == 0 and j == 0 and k == 0 and l == 0: continue # We don't care about all zero xors

                    input_xor = [i, j, k, l]
                    input_xor = BitString(0)

                    input_xor.set_nibble(0, l)
                    input_xor.set_nibble(1, k)
                    input_xor.set_nibble(2, j)
                    input_xor.set_nibble(3, i)

                    output_xor, _, preference = find_differential_trail(input_xor, diff_dist_table, round_num)

                    differential_trails.append((preference, input_xor, output_xor))

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

    current_xor = BitString(input_xor.bit_string)

    for r in range(round_num):
        # XOR doesn't change over key addition, so we can just ignore it

        # XOR going through sbox changes the probability (non-linear)
        for i in range(4):
            if current_xor.get_nibble(i) > 0: # SBOX is active

                # Get max entry in diff_dist row and adjust probability based on that
                max_count = max(diff_dist_table[current_xor.get_nibble(i)])
                most_probable_output_xor = diff_dist_table[current_xor.get_nibble(i)].index(max_count)

                probability *= max_count / len(diff_dist_table)

                current_xor.set_nibble(i, most_probable_output_xor)

        # XOR changes over permutation, but the probability is not affected (linear)
        permutate(current_xor, PBOX)


    # If we get a highly probable trail which has all the final SBOXes active,
    # we'll have to break a whole round key at once. It's much better to find
    # a trail with few final SBOXes active so we can break smaller portions of
    # the round key at a time. This is why we assign a "preference" to each
    # trail which is a function of the trail's probability and its number of
    # final active SBOXes.

    num_final_active_sboxes = 0

    if current_xor.get_nibble(0) > 0: num_final_active_sboxes += 1
    if current_xor.get_nibble(1) > 0: num_final_active_sboxes += 1
    if current_xor.get_nibble(2) > 0: num_final_active_sboxes += 1
    if current_xor.get_nibble(3) > 0: num_final_active_sboxes += 1

    preference = probability

    # 1 active SBOX: perfect
    # 2 active SBOXes: the key bits are broken within a couple of seconds. We 
    #                  won't adjust preference since it's fast enough and only
    #                  1 active SBOX is very unlikely anyway
    # 3 active SBOXes: could take ~10 sec so divide preference by some number
    #                  to discourage using it. Using 4 because it works well.
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
    return BitString(random.randint(0, 0xffff))



""" --- SPN CIPHER IMPLEMENTATION --- """

def encrypt(state, key1, key2, key3, key4, key5):
    add_round_key(state, key1)
    substitute(state, SBOX)
    permutate(state, PBOX)

    add_round_key(state, key2)
    substitute(state, SBOX)
    permutate(state, PBOX)

    add_round_key(state, key3)
    substitute(state, SBOX)
    permutate(state, PBOX)

    add_round_key(state, key4)
    substitute(state, SBOX)

    add_round_key(state, key5)

def decrypt(state, key1, key2, key3, key4, key5):
    add_round_key(state, key5)

    substitute(state, INV_SBOX)
    add_round_key(state, key4)

    permutate(state, INV_PBOX)
    substitute(state, INV_SBOX)
    add_round_key(state, key3)

    permutate(state, INV_PBOX)
    substitute(state, INV_SBOX)
    add_round_key(state, key2)

    permutate(state, INV_PBOX)
    substitute(state, INV_SBOX)
    add_round_key(state, key1)

def add_round_key(state, key):
    state.bit_string ^= key.bit_string

def substitute(state, sbox):
    new_state = BitString(0)
    bit_string = state.bit_string

    new_state.set_nibble(0, sbox[state.get_nibble(0)])
    new_state.set_nibble(1, sbox[state.get_nibble(1)])
    new_state.set_nibble(2, sbox[state.get_nibble(2)])
    new_state.set_nibble(3, sbox[state.get_nibble(3)])

    state.bit_string = new_state.bit_string

def permutate(state, pbox):
    new_state = BitString(0)
    bit_string = state.bit_string

    new_state.set_bit(0, state.get_bit(pbox[0]))
    new_state.set_bit(1, state.get_bit(pbox[1]))
    new_state.set_bit(2, state.get_bit(pbox[2]))
    new_state.set_bit(3, state.get_bit(pbox[3]))
    new_state.set_bit(4, state.get_bit(pbox[4]))
    new_state.set_bit(5, state.get_bit(pbox[5]))
    new_state.set_bit(6, state.get_bit(pbox[6]))
    new_state.set_bit(7, state.get_bit(pbox[7]))
    new_state.set_bit(8, state.get_bit(pbox[8]))
    new_state.set_bit(9, state.get_bit(pbox[9]))
    new_state.set_bit(10, state.get_bit(pbox[10]))
    new_state.set_bit(11, state.get_bit(pbox[11]))
    new_state.set_bit(12, state.get_bit(pbox[12]))
    new_state.set_bit(13, state.get_bit(pbox[13]))
    new_state.set_bit(14, state.get_bit(pbox[14]))
    new_state.set_bit(15, state.get_bit(pbox[15]))

    state.bit_string = new_state.bit_string



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

    if KEY1 < BitString(0) or KEY1 > BitString(0xffff):
        sys.exit('Error: KEY1 should be a value between 0 and 0xffff')

    if KEY2 < BitString(0) or KEY2 > BitString(0xffff):
        sys.exit('Error: KEY2 should be a value between 0 and 0xffff')

    if KEY3 < BitString(0) or KEY3 > BitString(0xffff):
        sys.exit('Error: KEY3 should be a value between 0 and 0xffff')

    if KEY4 < BitString(0) or KEY4 > BitString(0xffff):
        sys.exit('Error: KEY4 should be a value between 0 and 0xffff')

    if KEY5 < BitString(0) or KEY5 > BitString(0xffff):
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
