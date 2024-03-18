import numpy as np
import os
import binascii


class Trivium:

    def __init__(self, key, IV):
        #Input key and IV as lists of integers (1s and 0s only)
        self.output = ''
        self.S = np.zeros(dtype=int, shape=288)

        #Loading key for initializtion
        for i in range(len(key)):
            self.S[i] = key[i]

        #Loading IV for initializtion
        for j in range(len(IV)):
            self.S[j+93] = IV[j]

        #Initialization of last three bits, per Trivium specifications
        self.S[285], self.S[286], self.S[287] = 1,1,1

        #Initialization of Trivium algorithm
        for k in range(4*288):
            self.iterate()

    def iterate(self):
    #One iteration of the Trivium algorithm, with output of one bit.
        T1 = np.bitwise_xor(self.S[65], self.S[92])
        T2 = np.bitwise_xor(self.S[161], self.S[176])
        T3 = np.bitwise_xor(self.S[242], self.S[287])

        Z = np.bitwise_xor(np.bitwise_xor(T1, T2), T3)

        T1 = np.bitwise_xor(T1, np.bitwise_xor(self.S[170], np.bitwise_and(self.S[90], self.S[91])))
        T2 = np.bitwise_xor(T2, np.bitwise_xor(self.S[263], np.bitwise_and(self.S[174], self.S[175])))
        T3 = np.bitwise_xor(T3, np.bitwise_xor(self.S[68], np.bitwise_and(self.S[285], self.S[286])))

        for a in range(92, 0, -1):
            self.S[a] = self.S[a - 1]
        self.S[0] = T3

        for b in range(176, 93, -1):
            self.S[b] = self.S[b - 1]
        self.S[93] = T1

        for c in range(287, 178, -1):
            self.S[c] = self.S[c - 1]
        self.S[178] = T2

        self.output += str(Z.item())

        return Z.item()

    def get(self):
    #Return cumulative post-initialization output bits as a string
        return self.output[4*288:]