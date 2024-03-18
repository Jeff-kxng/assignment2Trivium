import argparse
import secrets
from trivium import Trivium


def get_random_bits(bitnumber):
    randbits = secrets.randbits(bitnumber)
    randstring = '{0:080b}'.format(randbits)
    return list(randstring)

def bits_from_string(string):
    stringbits = ''
    for char in string:
        charbyte = '{0:08b}'.format(ord(char))
        stringbits += charbyte
    return list(stringbits)

def main():

    # Command line options (-n,-k,-i,-b) with argparse module:
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--number', type=int, help='number of output bits')
    parser.add_argument('-k', '--key', type=str, help='input key')
    parser.add_argument('-i', '--ivector', type=str, help='input IV (initiation vector)')
    parser.add_argument('-b', '--binary', action='store_true', help='binary output')
    args = parser.parse_args()

    # Set variables with command-line inputs
    number = args.number if args.number is not None else 10  # Default value of 10

    # Get key as bitlist
    key = args.key
    if key:
        key = bits_from_string(key)
    else:
        key = get_random_bits(80)

    # Get initiation vector as bitlist
    ivector = args.ivector
    if ivector:
        ivector = bits_from_string(ivector)
    else:
        ivector = get_random_bits(80)

    # Flag for binary output (default output is hex)
    binary = args.binary


    # Instantiate Trivium object
    t = Trivium(key, ivector)


    # Iterate n times to produce n bits
    for i in range(number):
        t.iterate()


    # Output bitstream, IV, key
    output = t.get()
    output_IV = ''.join(ivector)
    output_key = ''.join(key)

    if not binary:
        output = hex(int(output,2))
        output_IV = hex(int(output_IV,2))
        output_key = hex(int(output_key,2))

    print(f'Bitstream: {output}')
    print(f'IV: {output_IV}')
    print(f'Key: {output_key}')


if __name__ == '__main__':
    main()