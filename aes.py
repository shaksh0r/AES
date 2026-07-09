from aes_helpers import Sbox, InvSbox, Rcon, Mixer, InvMixer, gf_mult
class AES:
    def __init__(self,key:str,mode:str,plaintext):
        self.key = key
        self.mode = mode
        self.plaintext = plaintext


    def process_key(self):
        key = self.key.encode('ascii')
        self.key = self.padding(key)
    
    def padding(self,data):
        data_length = len(data)
        print(data_length)
        if data_length % 4 == 0:
            return data
        

        padding_needed = 4*((data_length // 4) + 1) - data_length
        self.block_size = data_length + padding_needed
        padding = str(padding_needed).encode('ascii')

        for i in range (padding_needed):
            data += padding
        
        return data
    
    def process_plain_text(self):
        byte_text = self.plaintext.encode('ascii')
        byte_text = self.padding(byte_text)
        self.byte_text = byte_text

    def subBytes(self):
        subBytes_text = []
        for i in range(len(self.byte_text)):
            byte_value = self.byte_text[i]
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

    def print_text(self,text:bytes):
        count = 0
        for b in text:
            print(f"{b}  ",end='')
            count += 1
            if count % 4 == 0:
                print()
    

aes = AES('abcde',mode="ECB",plaintext="1234567812345678")
aes.process_key()
aes.process_plain_text()
aes.subBytes()
aes.shiftRows()

