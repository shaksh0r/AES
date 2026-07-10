from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
import os
import random
import math
import hashlib
import time


def generate_k_bit_odd(k):
    lower = 2**(k-1) + 1 
    upper = 2**k - 1   
    return random.randrange(lower, upper, 2)


def miller_rabin_test(n, k=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(k):
    while True:
        odd = generate_k_bit_odd(k)
        if miller_rabin_test(odd):
            return odd

class DiffieHellman:
    def __init__(self, key_size=128, seed=None):
        if seed is not None:
            random.seed(seed)

        self.key_size = key_size
        self.P, self.g = self.generate_params()


    def generate_private_key(self):
        return random.randrange(2**(self.key_size - 1), 2**self.key_size)

    def compute_public_key(self, private_key):
        return pow(self.g, private_key, self.P)

    def compute_shared_secret(self, my_private_key, their_public_key):
        return pow(their_public_key, my_private_key, self.P)


    def generate_params(self):
        k = self.key_size
        while True:
            r = generate_prime(k - 1)
            P = 2 * r + 1
            if P.bit_length() == k and miller_rabin_test(P):
                for g in range(2, 10000):
                    if pow(g, r, P) != 1:
                        return P, g

print("------------------------------------------------------------------------------------------")
print("                                     Computation time for                                 ")
print("         k     ---------------------------------------------------------------------------")
print("                         A                       B                 shared key s           ")
print("------------------------------------------------------------------------------------------")

for key in [128,192,256]:
    dh = DiffieHellman(key_size=128, seed=42)
    A_time = 0
    B_time = 0
    shared_key_time = 0
    iteration_no = 5
    for iteration in range(iteration_no):
        A_start = time.process_time()
        ka = dh.generate_private_key()
        A  = dh.compute_public_key(ka)
        A_end = time.process_time()
        A_time += (A_end-A_start)
        B_start = time.process_time()
        kb = dh.generate_private_key()
        B  = dh.compute_public_key(kb)
        B_end = time.process_time()
        B_time += (B_end-B_start)

        shared_start = time.process_time()
        shared_key = dh.compute_shared_secret(ka, B)
        shared_end = time.process_time()

        shared_key_time += (shared_end-shared_start)
    
    A_average = A_time / iteration_no
    B_average = B_time / iteration_no
    shared_key_average = shared_key_time / iteration_no
    print(f"       {key}           {A_average:.5g}         {B_average:.5g}                {shared_key_average:.5g}")




# s_a = str(s_a).encode()
# salt = os.urandom(16)
# hashed_key = hashlib.pbkdf2_hmac(
#     'sha256',
#     s_a,
#     salt,
#     100000,
#     dklen=16
# )




