class BitString():
    def __init__(self, bit_string):
        self.bit_string = bit_string

    def count_one_bits(self):
        """
        Returns the number of 1 bits in self.bit_string
        """

        count = 0
        bs = self.bit_string

        while bs > 0:
            if bs & 1 == 1: count += 1

            bs >>= 1

        return count

    def get_bit(self, index):
        """
        Returns the index-th bit out of self.bit_string

        Zero indexed and index zero is the least significant bit
        """

        mask = 0x1 << index
        nibble = self.bit_string & mask
        nibble = nibble >> index

        return nibble

    def set_bit(self, index, value):
        """
        Sets the index-th bit in self.bit_string. Returns the new bit_string

        Value should be either 0 or 1. Otherwise no change

        Zero indexed and index zero is the least significant bit
        """

        if value != 0 and value != 1:
            return None

        mask = 0x1 << index
        self.bit_string &= ~mask
        self.bit_string ^= (value << index)

        return self.bit_string

    def get_nibble(self, index):
        """
        Returns the index-th nibble out of self.bit_string

        Zero indexed and index zero is the least significant bit
        """

        index *= 4

        mask = 0xf << index
        nibble = self.bit_string & mask
        nibble = nibble >> index

        return nibble

    def set_nibble(self, index, value):
        """
        Sets the index-th nibble in self.bit_string. Returns the new bit_string

        Value should be a number between 0 and 0xf. Otherwise no change

        Zero indexed and index zero is the least significant bit
        """

        if value < 0 or value > 0xf:
            return None

        index *= 4

        mask = 0xf << index
        self.bit_string &= ~mask
        self.bit_string ^= (value << index)

        return self.bit_string

    def __str__(self):
        return hex(self.bit_string)

    def __lt__(self, other):
        return (self.bit_string < other.bit_string)
