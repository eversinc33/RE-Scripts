import struct

class TEADecryptor:
    def __init__(self):
        self.DELTA = 0x9e3779b9  # Golden ratio constant
        self.MASK = 0xffffffff   # 32-bit mask
    
    def decrypt_block(self, v0, v1, key):
        k0, k1, k2, k3 = key
        
        # first dword
        temp1 = ((v0 << 4) + k2) & self.MASK
        temp2 = (v0 + self.DELTA) & self.MASK  
        temp3 = ((v0 >> 5) + k3) & self.MASK
        
        decrypt_val = temp1 ^ temp2 ^ temp3
        v1 = (v1 - decrypt_val) & self.MASK
        
        # Second dword
        temp1 = ((v1 << 4) + k0) & self.MASK
        temp2 = (v1 + self.DELTA) & self.MASK
        temp3 = ((v1 >> 5) + k1) & self.MASK
        
        decrypt_val = temp1 ^ temp2 ^ temp3
        v0 = (v0 - decrypt_val) & self.MASK
        
        return v0, v1
    
def main():
    decryptor = TEADecryptor()
    
    key = [
        0x14820285,  # key_bytes_chunk_0 
        0x26820323,  # key_bytes_chunk_1 
        0x35223562,  # key_bytes_chunk_2
        0x41256421   # key_bytes_chunk_3 
    ]
    
    with open("encrypted.bin", 'rb') as f_in:
        data = f_in.read()
    
    decrypted_data = bytearray()
    
    # Process in 64-bit chunks
    for i in range(0, len(data), 8):
        # Get 64-bit chunk (pad with zeros if needed)
        chunk = data[i:i+8]
        if len(chunk) < 8:
            chunk = chunk.ljust(8, b'\x00')
        
        # Convert to two 32-bit integers (little-endian)
        v0, v1 = struct.unpack('<2I', chunk)
        
        # Apply single round decryption
        decrypted_v0, decrypted_v1 = decryptor.decrypt_block(v0, v1, key)
        
        # Convert back to bytes and append
        decrypted_chunk = struct.pack('<2I', decrypted_v0, decrypted_v1)
        decrypted_data.extend(decrypted_chunk)
        
    with open("decrypted.txt", 'wb') as f_out:
        f_out.write(decrypted_data)

if __name__ == "__main__":
    main()