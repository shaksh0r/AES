class AES:

    def __init__(self,key:bytes,mode:str,plaintext):
        self.key = key
        self.mode = mode
        self.plaintext = plaintext


    def process_key(self):
        key = self.key
        print(type(key))

        key_length = len(key)
        print(key_length)
        if key_length % 8 == 0:
            self.block_size = key_length
            return
        

        padding_needed = 8*((key_length // 8) + 1) - key_length
        self.block_size = key_length + padding_needed
        padding = str(padding_needed).encode('ascii')

        for i in range (padding_needed):
            key += padding
        
        self.key = key
    
    def split_into_blocks(self):
        


    def print_key(self):
        print(self.key)
    

# aes = AES(b'abcde',mode="ECB",plaintext="abkdljhl")
# aes.process_key()
# aes.print_key()          