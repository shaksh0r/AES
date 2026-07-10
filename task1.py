import os
import random
import time
import base64

from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
class AES:
    def __init__(self,key,mode:str,plaintext):
        self.key = key
        self.mode = mode
        self.plaintext = plaintext


    def process_key(self):
        text_key = self.key
        key = self.key.encode('ascii')
        self.key = bytearray(self.padding(key))
        # print("Key:")
        # print(f"In ASCII: {text_key}")
        # print(f"In Hex: {self.key.hex(sep=' ')}")

    def set_key_bytes(self, key_bytes: bytes):
        self.key = bytearray(key_bytes)
    
    def padding(self,data):
        data_length = len(data)
        if data_length % 16 == 0:
            return data
        

        padding_needed = 16*((data_length // 16) + 1) - data_length
        padding_byte = padding_needed
        for i in range(padding_needed):
            data += bytes([padding_byte])

        
        return data
    def process_plain_text(self):
        # print(f"In ASCII: {plain_text}")
        byte_text = self.plaintext.encode('ascii')
        # print(f"In Hex: {byte_text.hex(sep=' ')}")
        byte_text = self.padding(byte_text)
        self.byte_text = bytearray(byte_text)
        # print(f"In ASCII (After Padding): {padded_text}")
        # print(f"In Hex (After Padding): {byte_text.hex(sep=' ')}")

    def subBytes(self,byte_text):
        subBytes_text = []
        for byte_no in range(len(byte_text)):
            byte_value = byte_text[byte_no]
            s_value = Sbox[byte_value]
            subBytes_text.append(s_value)

        self.subBytes_text = subBytes_text
    
    def shiftRows(self):
        matrix = bytearray(self.subBytes_text)

        row_count = len(matrix) // 4
        for row_no in range(row_count):
            row = matrix[row_no*4:row_no*4+4]
            new_row = row.copy()
            row_size = len(row)
            for byte_no in range(row_size):
                if (byte_no-row_no) < 0:
                    new_row[-abs(byte_no-row_no)] = row[byte_no]
                else:
                    new_row[(byte_no-row_no)] = row[byte_no]

            matrix[row_no*4:row_no*4+4] = new_row

        self.shiftrows_matrix = matrix
    def mixColumns(self):
        matrix = self.shiftrows_matrix
        column_count = 4

        for column_no in range(column_count):
            column = matrix[column_no::4]
            new_column = column.copy()

            for byte_no in range(4):
                xor_sum = 0
                for xor_byte_no in range(4):
                    a = column[xor_byte_no]
                    b = Mixer[byte_no][xor_byte_no]
                    xor_sum ^= gf_mult(a,b)

                new_column[byte_no] = xor_sum

            matrix[column_no::4] = new_column
        
        self.mixColumns_text = matrix

    def key_scheduling(self,scheduled_key,iteration):
        key = bytearray(scheduled_key)

        last_column = key[3::4]
        new_column = last_column.copy()
        new_column[0] = last_column[1]
        new_column[1] = last_column[2]
        new_column[2] = last_column[3]
        new_column[3] = last_column[0]

        for byte_no in range(4):
            new_column[byte_no] = Sbox[new_column[byte_no]]
        
        new_column[0] = new_column[0] ^ Rcon[iteration]

        first_column = key[0::4]

        for byte_no in range(4):
            new_column[byte_no] = first_column[byte_no] ^ new_column[byte_no]
        
        new_key = key.copy()

        new_key[0::4] = new_column

        for column_no in range(1,4):

            previous_column = new_key[column_no-1::4]
            previous_key_column = key[column_no::4]

            new_column = previous_column.copy()
            for byte_no in range(4):

                new_column[byte_no] = previous_column[byte_no] ^ previous_key_column[byte_no]
            
            new_key[column_no::4] = new_column
        
        return new_key

                

    def addRoundKey(self,scheduled_key,iteration,last_iteration=False):
        encrypted_text = scheduled_key.copy()
        if not last_iteration:
            for byte_no in range(16):
                encrypted_text[byte_no] = scheduled_key[byte_no] ^ self.mixColumns_text[byte_no]

            
        else:
            for byte_no in range(16):
                encrypted_text[byte_no] = scheduled_key[byte_no] ^ self.shiftrows_matrix[byte_no]

        
        return encrypted_text


    def ECB(self,iteration_no):
        schedule_key = self.key
        encrypted_text = self.byte_text.copy()
        encrypted_block = None

        key_schedule_total = 0.0
        encryption_total = 0.0
        total_rounds = iteration_no + 1
        total_blocks = len(encrypted_text) // 16

        for iteration in range(total_rounds):
            round_start = time.perf_counter()

            block_no = 0
            for block_no in range(total_blocks):
                self.subBytes(encrypted_text[block_no*16:block_no*16+16])
                self.shiftRows()
                if iteration != iteration_no:
                    self.mixColumns()
                
                encrypted_block = self.addRoundKey(schedule_key,iteration,iteration == iteration_no)
                encrypted_text[block_no*16:block_no*16+16] = encrypted_block
                block_no +=1

            round_end = time.perf_counter()
            encryption_total += (round_end - round_start)

            ks_start = time.perf_counter()
            schedule_key = self.key_scheduling(schedule_key,iteration+1)
            ks_end = time.perf_counter()
            key_schedule_total += (ks_end - ks_start)

        self.ciphered_text = bytes(encrypted_text)
        self.encryption_total_round_calls = total_rounds
        self.key_schedule_total = key_schedule_total
        self.encryption_total = encryption_total

        return encrypted_text
    
    def CBC(self,iteration_no):
        plaintext = self.byte_text.copy()
        random_IV = bytearray(os.urandom(16))
        cipher_text = random_IV

        total_block = len(plaintext) // 16
        total_rounds = iteration_no + 1

        key_schedule_total = 0.0
        encryption_total = 0.0

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
            while iteration < total_rounds:
                round_start = time.perf_counter()

                self.subBytes(encrypted_block)
                self.shiftRows()
                if iteration != iteration_no:
                    self.mixColumns()
                
                encrypted_block = self.addRoundKey(schedule_key,iteration,iteration == iteration_no)

                round_end = time.perf_counter()
                encryption_total += (round_end - round_start)

                ks_start = time.perf_counter()
                schedule_key = self.key_scheduling(schedule_key,iteration+1) 
                ks_end = time.perf_counter()
                key_schedule_total += (ks_end - ks_start)

                iteration += 1

            cipher_text =  encrypted_block
            final_encryption.append(encrypted_block)
            block_no += 1

        self.encryption_total_round_calls = total_rounds * total_block

        ciphered_text = bytes(final_encryption[0] + final_encryption[1])
        self.ciphered_text = ciphered_text
        self.key_schedule_total = key_schedule_total
        self.encryption_total = encryption_total

        self.cbc_encrypted_text = final_encryption
        return final_encryption
    
                
                


    def invSubBytes(self):
        invSubBytes_text = []
        for byte_no in range(len(self.inv_shiftrows_matrix)):
            byte_value = self.inv_shiftrows_matrix[byte_no]
            s_value = InvSbox[byte_value]
            invSubBytes_text.append(s_value)

        self.invSubBytes_text = invSubBytes_text

    def invShiftRows(self):
        matrix = bytearray(self.inv_mixcolumns_matrix)

        row_count = len(matrix) // 4
        for row_no in range(row_count):
            row = matrix[row_no*4:row_no*4+4]
            new_row = row.copy()
            row_size = len(row)
            for byte_no in range(row_size):
                if (byte_no + row_no) >= 4:
                    new_row[(byte_no + row_no) - 4] = row[byte_no]
                else:
                    new_row[(byte_no + row_no)] = row[byte_no]

            matrix[row_no*4:row_no*4+4] = new_row
        self.inv_shiftrows_matrix = matrix

    def invMixColumns(self):
        matrix = bytearray(self.invAddRoundKey_text)

        for column_no in range(4):
            column = matrix[column_no::4]
            new_column = column.copy()

            for byte_no in range(4):
                xor_sum = 0
                for xor_byte_no in range(4):
                    a = column[xor_byte_no]
                    b = InvMixer[byte_no][xor_byte_no]
                    xor_sum ^= gf_mult(a, b)

                new_column[byte_no] = xor_sum

            matrix[column_no::4] = new_column

        self.inv_mixcolumns_matrix = matrix

    def invAddRoundKey(self,byte_text,scheduled_key):
        invAddRoundKey_text = bytearray(byte_text)
        for byte_number in range(16):
            invAddRoundKey_text[byte_number] = byte_text[byte_number] ^ scheduled_key[byte_number]

        self.invAddRoundKey_text = invAddRoundKey_text

    def generate_round_keys(self,iteration_no):
        round_keys = []
        schedule_key = self.key
        round_keys.append(schedule_key.copy())

        iteration = 1
        while iteration <= iteration_no:
            schedule_key = self.key_scheduling(schedule_key,iteration)
            round_keys.append(schedule_key.copy())
            iteration += 1

        return round_keys

    def remove_padding(self,data):
        data_length = len(data)
        if data_length == 0:
            return data

        padding_byte = data[data_length - 1]

        if padding_byte < 1 or padding_byte > 15:
            return data

        i = data_length - padding_byte
        while i < data_length:
            if data[i] != padding_byte:
                return data
            i += 1

        return data[:data_length - padding_byte]

    def ECB_decrypt(self,iteration_no):
        round_keys = self.generate_round_keys(iteration_no)
        decrypted_text = self.byte_text.copy()

        decryption_total = 0.0
        total_rounds = iteration_no + 1
        total_blocks = len(decrypted_text) // 16

        round_index = iteration_no
        while round_index >= 0:
            round_start = time.perf_counter()

            block_no = 0
            for block_no in range(total_blocks):
                block = decrypted_text[block_no*16:block_no*16+16]

                self.invAddRoundKey(block,round_keys[round_index])

                if round_index == iteration_no:
                    self.inv_mixcolumns_matrix = self.invAddRoundKey_text
                    self.invShiftRows()
                    self.invSubBytes()
                    decrypted_block = self.invSubBytes_text
                else:
                    self.invMixColumns()
                    self.invShiftRows()
                    self.invSubBytes()
                    decrypted_block = self.invSubBytes_text

                decrypted_text[block_no*16:block_no*16+16] = bytearray(decrypted_block)
                block_no +=1

            round_end = time.perf_counter()
            decryption_total += (round_end - round_start)

            round_index -= 1

        unpadded_text = self.remove_padding(decrypted_text)
        self.decrypted_text = bytes(decrypted_text)
        self.decrypted_unpadded_text = bytes(unpadded_text)

        # print("\nDeciphered Text:")
        # print("Before Unpadding:")
        # print(f"In HEX: {decrypted_text.hex(sep=' ')}")
        # print(f"In ASCII: {decrypted_text.decode('utf-8', errors='replace')}")
        # print("After Unpadding:")
        # print(f"In ASCII: {unpadded_text.decode('utf-8', errors='replace')}")
        # print(f"In HEX: {unpadded_text.hex(sep=' ')}")

        self.decryption_total_round_calls = total_rounds
        self.decryption_total = decryption_total

        return unpadded_text

    def CBC_decrypt(self,iteration_no):
        round_keys = self.generate_round_keys(iteration_no)

        iv = self.cbc_encrypted_text[0]
        cipher_blocks = self.cbc_encrypted_text[1:]

        decrypted_text = bytearray()

        decryption_total = 0.0
        total_rounds = iteration_no + 1
        total_blocks = len(cipher_blocks)

        block_no = 0
        while block_no < total_blocks:
            encrypted_block = cipher_blocks[block_no]

            decrypted_block = bytearray(encrypted_block)

            round_index = iteration_no
            while round_index >= 0:
                round_start = time.perf_counter()

                self.invAddRoundKey(decrypted_block,round_keys[round_index])

                if round_index == iteration_no:
                    self.inv_mixcolumns_matrix = self.invAddRoundKey_text
                    self.invShiftRows()
                    self.invSubBytes()
                    decrypted_block = self.invSubBytes_text
                else:
                    self.invMixColumns()
                    self.invShiftRows()
                    self.invSubBytes()
                    decrypted_block = self.invSubBytes_text

                round_end = time.perf_counter()
                decryption_total += (round_end - round_start)

                round_index -= 1

            previous_block = iv
            if block_no != 0:
                previous_block = cipher_blocks[block_no - 1]

            decrypted_block = bytearray(decrypted_block)
            byte_number = 0
            while byte_number < 16:
                decrypted_block[byte_number] = decrypted_block[byte_number] ^ previous_block[byte_number]
                byte_number += 1

            decrypted_text.extend(decrypted_block)
            block_no += 1

        unpadded_text = self.remove_padding(decrypted_text)
        self.decrypted_text = bytes(decrypted_text)
        self.decrypted_unpadded_text = bytes(unpadded_text)
        # print("\nDeciphered Text:")
        # print("Before Unpadding:")
        # print(f"In HEX: {decrypted_text.hex(sep=' ')}")
        # print(f"In ASCII: {decrypted_text.decode('utf-8', errors='replace')}")
        # print("After Unpadding:")
        # print(f"In ASCII: {unpadded_decrypted_text.decode('utf-8', errors='replace')}")
        # print(f"In HEX: {unpadded_decrypted_text.hex(sep=' ')}")

        self.decryption_total_round_calls = total_rounds * total_blocks
        self.decryption_total = decryption_total

        return unpadded_text
    
    def print_report(self):
        print("Key:")
        print(f"In ASCII: {self.key.decode('utf-8')}")
        print(f"In Hex: {self.key.hex(sep=' ')}")

        print()
        print()

        print("Plain Text:")
        print(f"In ASCII: {self.plaintext}")
        print(f"In Hex: {self.plaintext.encode('ascii').hex(sep=' ')}")
        print(f"In ASCII (After Padding): {self.byte_text.decode('utf-8')}")
        print(f"In Hex (After Padding): {self.byte_text.hex(sep=' ')}")

        print()
        print()

        print("Ciphered Text:")
        if self.mode == "CBC":
            print("IV is the first 16 bytes, followed by the actual ciphertext")
        print(f"In HEX: {self.ciphered_text.hex(sep=' ')}")
        print(f"In ASCII: {base64.b64encode(self.ciphered_text).decode('ascii')}")

        print()
        print()

        print("Deciphered Text:")
        print("Before Unpadding:")
        print(f"In HEX: {self.decrypted_text.hex(sep=' ')}")
        print(f"In ASCII: {self.decrypted_text.decode('utf-8', errors='replace')}")
        print("After Unpadding:")
        print(f"In ASCII: {self.decrypted_unpadded_text.decode('utf-8', errors='replace')}")
        print(f"In HEX: {self.decrypted_unpadded_text.hex(sep=' ')}")

        print()
        print()

        print("Exection Time Details:")
        print(f"Key Schedule Time: total = {aes.key_schedule_total*1000:.4f} ms, per call = {aes.key_schedule_total/10*1000:.4f} ms")
        print(f"Encryption Time: total = {aes.encryption_total*1000:.4f} ms, per round = {aes.encryption_total/aes.encryption_total_round_calls*1000:.4f} ms")
        print(f"Decryption Time: total = {aes.decryption_total*1000:.4f} ms, per round = {aes.decryption_total/aes.decryption_total_round_calls*1000:.4f} ms")

    def run(self,):
        mode = self.mode
        self.process_key()
        self.process_plain_text()

        if mode == "CBC":
            encrypted = self.CBC(9)
            dec = self.CBC_decrypt(9)
        elif mode == "ECB":
            encrypted = self.ECB(9)
            dec = self.ECB_decrypt(9)

        self.print_report()

if __name__ == "__main__":
    aes = AES(key='BUET CSE20 Batch',mode="ECB",plaintext="We need picnic")
    aes.run()


    

    # print("Exection Time Details:")
    # print(f"Key Schedule Time: total = {aes.key_schedule_total*1000:.4f} ms, per call = {aes.key_schedule_total/10*1000:.4f} ms")
    # print(f"Encryption Time: total = {aes.encryption_total*1000:.4f} ms, per round = {aes.encryption_total/aes.encryption_total_round_calls*1000:.4f} ms")
    # print(f"Decryption Time: total = {aes.decryption_total*1000:.4f} ms, per round = {aes.decryption_total/aes.decryption_total_round_calls*1000:.4f} ms")




