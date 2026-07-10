import os
import random

from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
class AES:
    def __init__(self,key,mode:str,plaintext):
        self.key = key
        self.mode = mode
        self.plaintext = plaintext


    def process_key(self):
        key = self.key.encode('ascii')
        self.key = bytearray(self.padding(key))
    
    def padding(self,data):
        data_length = len(data)
        print(data_length)
        if data_length % 16 == 0:
            return data
        

        padding_needed = 16*((data_length // 16) + 1) - data_length
        padding_byte = padding_needed
        for i in range(padding_needed):
            data += bytes([padding_byte])

        
        return data
    
    def process_plain_text(self):
        byte_text = self.plaintext.encode('ascii')
        byte_text = self.padding(byte_text)
        self.byte_text = bytearray(byte_text)

    def subBytes(self,byte_text):
        subBytes_text = []
        for i in range(len(byte_text)):
            byte_value = byte_text[i]
            s_value = Sbox[byte_value]
            subBytes_text.append(s_value)

        self.subBytes_text = subBytes_text
    
    def shiftRows(self):
        matrix = bytearray(self.subBytes_text)

        i = 0
        while i*4 < len(matrix):

            row = matrix[i*4:i*4+4]
            new_row = row.copy()
            j = 0
            while j<len(row):
                if (j-i) < 0:
                    new_row[-abs(j-i)] = row[j]
                else:
                    new_row[(j-i)] = row[j]
                j += 1
            matrix[i*4:i*4+4] = new_row
            i += 1
        self.shiftRows_text = matrix
    def mixColumns(self):
        matrix = self.shiftRows_text

        column_count = 4
        i = 0
        while i < column_count:
            column = matrix[i::4]
            new_column = column.copy()
            j = 0
            while j < 4:
                k = 0
                xor_sum = 0
                while k < 4:
                    a = column[k]
                    b = Mixer[j][k]
                    xor_sum ^= gf_mult(a,b)
                    k+=1
                new_column[j] = xor_sum
                j += 1
            matrix[i::4] = new_column
            i += 1
        
        self.mixColumns_text = matrix

    def key_scheduling(self,scheduled_key,iteration):
        key = bytearray(scheduled_key)

        last_column = key[3::4]
        new_column = last_column.copy()
        new_column[0] = last_column[1]
        new_column[1] = last_column[2]
        new_column[2] = last_column[3]
        new_column[3] = last_column[0]

        i = 0
        while i<4:
            new_column[i] = Sbox[new_column[i]]
            i+=1
        
        new_column[0] = new_column[0] ^ Rcon[iteration]

        
        first_column = key[0::4]
        i = 0
        while i<4:
            new_column[i] = first_column[i] ^ new_column[i]
            i+=1
        
        new_key = key.copy()

        new_key[0::4] = new_column

        column_number = 1
        while column_number<4:

            byte_number = 0
            previous_column = new_key[column_number-1::4]
            previous_key_column = key[column_number::4]

            new_column = previous_column.copy()
            while byte_number<4:

                new_column[byte_number] = previous_column[byte_number] ^ previous_key_column[byte_number]


                byte_number += 1
            
            new_key[column_number::4] = new_column
            
            column_number += 1
        
        return new_key

                

    def addRoundKey(self,scheduled_key,iteration,last_iteration=False):
        encrypted_text = scheduled_key.copy()
        if not last_iteration:
            byte_number = 0
            while byte_number < 16:
                encrypted_text[byte_number] = scheduled_key[byte_number] ^ self.mixColumns_text[byte_number]
                
                byte_number += 1
            
        else:
            byte_number = 0
            while byte_number < 16:
                encrypted_text[byte_number] = scheduled_key[byte_number] ^ self.shiftRows_text[byte_number]
                
                byte_number += 1
        
        return encrypted_text


    def ECB(self,iteration_no):
        schedule_key = self.key
        cipher_text = self.byte_text.copy()
        encrypted_block = None
        for iteration in range(iteration_no+1):
            block_no = 0
            total_block = len(cipher_text) // 16

            for block_no in range(total_block):
                self.subBytes(cipher_text[block_no*16:block_no*16+16])
                self.shiftRows()
                if iteration != iteration_no:
                    self.mixColumns()
                
                encrypted_block = self.addRoundKey(schedule_key,iteration,iteration == iteration_no)
                cipher_text[block_no*16:block_no*16+16] = encrypted_block
                block_no +=1

            
            schedule_key = self.key_scheduling(schedule_key,iteration+1)
        
        return cipher_text
    
    def CBC(self,iteration_no):
        plaintext = self.byte_text.copy()
        random_IV = bytearray(os.urandom(16))
        cipher_text = random_IV

        total_block = len(plaintext) // 16

        block_no = 0
        final_encryption = [random_IV]

        while block_no < total_block:
            schedule_key = self.key
            block = plaintext[block_no * 16:block_no * 16 + 16]
            byte_no = 0
            while byte_no < 16:
                block[byte_no] = block[byte_no] ^ cipher_text[byte_no]

                byte_no += 1

            iteration = 0
            encrypted_block = block.copy()
            while iteration < (iteration_no+1):
                self.subBytes(encrypted_block)
                self.shiftRows()
                if iteration != iteration_no:
                    self.mixColumns()
                
                encrypted_block = self.addRoundKey(schedule_key,iteration,iteration == iteration_no)

                schedule_key = self.key_scheduling(schedule_key,iteration+1) 
                iteration += 1

            cipher_text =  encrypted_block
            final_encryption.append(encrypted_block)
            block_no += 1
        return final_encryption
    
    def generate_k_bit_odd(self,k):
        lower = 2**(k-1) + 1 
        upper = 2**k - 1   
        num = random.randrange(lower, upper, 2)
        return num

    def miller_rabin_test(self,n, k=40):
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
                
                
        


        





    def print_text(self,text:bytes):
        count = 0
        for b in text:
            print(f"{b}  ",end='')
            count += 1
            if count % 4 == 0:
                print()

    

aes = AES('1234567812345678',mode="ECB",plaintext="1234567812345678")
# aes.process_key()
# aes.process_plain_text()
# aes.subBytes()
# aes.shiftRows()
# aes.mixColumns()
key = "1234567812345678"






