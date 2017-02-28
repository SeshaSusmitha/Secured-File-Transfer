#!/usr/bin/env python
import sys
import math

BIT_LEN = 128

def blum_blum_shub(p = 7, q = 11):
	seed = None

	while not seed:
		seed = raw_input("Please enter seed for calculating Nonce:")

	m = p * q
	n = BIT_LEN
	xi = int(seed)
	finalval = 0

	for i in range(0, BIT_LEN):
		xiplus1 = (xi**2) % m
		xi = xiplus1
		output = xiplus1 % 2
		finalval = (finalval << 1) + output
	#return bin(finalval)
	return (finalval)

if __name__ == '__main__':
	print blum_blum_shub()
