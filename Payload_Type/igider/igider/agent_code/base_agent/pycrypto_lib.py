class igider:
    def encrypt(self, data):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from Crypto.Hash import HMAC, SHA256
        from Crypto.Random import get_random_bytes
        import base64
        import os

        if not self.agent_config["enc_key"]["value"] == "none" and len(data) > 0:
            # Decode the base64 encryption key
            key = base64.b64decode(self.agent_config["enc_key"]["enc_key"])
            
            # Generate a random IV (Initialization Vector)
            iv = get_random_bytes(16)
            
            # Create AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Pad the data to match block size (16 bytes for AES)
            padded_data = pad(data, AES.block_size)
            
            # Encrypt the data
            ct = cipher.encrypt(padded_data)
            
            # Create HMAC for authentication
            h = HMAC.new(key, digestmod=SHA256)
            h.update(iv + ct)
            hmac_digest = h.digest()
            
            # Combine IV, ciphertext, and HMAC
            output = iv + ct + hmac_digest
            
            return output
        else:
            return data

    def decrypt(self, data):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        from Crypto.Hash import HMAC, SHA256
        import base64
        
        if not self.agent_config["enc_key"]["value"] == "none":
            if len(data) > 0:
                # Decode the base64 decryption key
                key = base64.b64decode(self.agent_config["enc_key"]["dec_key"])
                
                # Extract UUID, IV, ciphertext, and HMAC
                uuid = data[:36]
                iv = data[36:52]
                ct = data[52:-32]
                received_hmac = data[-32:]
                
                # Verify HMAC for integrity
                h = HMAC.new(key, digestmod=SHA256)
                h.update(iv + ct)
                
                try:
                    # Verify HMAC (raises exception if invalid)
                    h.verify(received_hmac)
                    
                    # Create AES cipher for decryption
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    
                    # Decrypt the ciphertext
                    pt = cipher.decrypt(ct)
                    
                    # Remove padding
                    unpadded_data = unpad(pt, AES.block_size)
                    
                    # Return the decrypted data with UUID
                    return (uuid + unpadded_data).decode()
                except ValueError:
                    # HMAC verification failed
                    return ""
                except Exception as e:
                    # Other decryption errors
                    return ""
            else:
                return ""
        else:
            return data.decode()
            
    def derive_key(self, password, salt=None, iterations=100000):
        """
        Derive a cryptographic key from a password using PBKDF2
        """
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256
        from Crypto.Random import get_random_bytes
        import base64
        
        # Generate a random salt if not provided
        if salt is None:
            salt = get_random_bytes(16)
            
        # Derive a 32-byte key (256 bits) using PBKDF2
        key = PBKDF2(
            password.encode() if isinstance(password, str) else password,
            salt,
            dkLen=32,  # AES-256 key size
            count=iterations,
            hmac_hash_module=SHA256
        )
        
        return key, salt
        
    def generate_key_pair(self):
        """
        Generate a new AES encryption key and encode it as base64
        """
        from Crypto.Random import get_random_bytes
        import base64
        
        # Generate a random 32-byte (256-bit) key
        key = get_random_bytes(32)
        
        # Return base64 encoded key
        return base64.b64encode(key).decode()

    def encrypt_file(self, file_path, output_path, key):
        """
        Encrypt a file using AES-CBC with HMAC-SHA256 authentication
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        from Crypto.Hash import HMAC, SHA256
        from Crypto.Random import get_random_bytes
        import base64
        import os
        
        # Decode the base64 key if provided as string
        if isinstance(key, str):
            key = base64.b64decode(key)
        
        # Generate a random IV
        iv = get_random_bytes(16)
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Initialize HMAC
        h = HMAC.new(key, digestmod=SHA256)
        h.update(iv)  # Include IV in HMAC
        
        try:
            # Create output file
            with open(output_path, 'wb') as out_file:
                # Write IV to output file
                out_file.write(iv)
                
                # Process the input file in chunks to handle large files
                with open(file_path, 'rb') as in_file:
                    # Process all blocks except the last one
                    chunk_size = 64 * 1024  # 64KB chunks
                    
                    while True:
                        chunk = in_file.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            # Apply padding to the last block
                            chunk = pad(chunk, AES.block_size)
                            encrypted_chunk = cipher.encrypt(chunk)
                            out_file.write(encrypted_chunk)
                            h.update(encrypted_chunk)
                            break
                        else:
                            # Encrypt full block
                            encrypted_chunk = cipher.encrypt(chunk)
                            out_file.write(encrypted_chunk)
                            h.update(encrypted_chunk)
                
                # Write HMAC to the end of the file
                out_file.write(h.digest())
                
            return True
        except Exception as e:
            # Handle encryption errors
            return False

    def decrypt_file(self, file_path, output_path, key):
        """
        Decrypt a file encrypted with encrypt_file method
        """
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        from Crypto.Hash import HMAC, SHA256
        import base64
        import os
        
        # Decode the base64 key if provided as string
        if isinstance(key, str):
            key = base64.b64decode(key)
        
        try:
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # File must be at least IV (16) + HMAC (32) bytes
            if file_size < 48:
                return False
            
            with open(file_path, 'rb') as in_file:
                # Read IV (first 16 bytes)
                iv = in_file.read(16)
                
                # Create AES cipher for decryption
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                # Initialize HMAC
                h = HMAC.new(key, digestmod=SHA256)
                h.update(iv)
                
                # Calculate where HMAC starts
                hmac_start = file_size - 32
                
                # Create output file
                with open(output_path, 'wb') as out_file:
                    # Current position after reading IV
                    current_pos = 16
                    
                    # Process file in chunks
                    chunk_size = 64 * 1024  # 64KB chunks
                    
                    while current_pos < hmac_start:
                        # Calculate next chunk size
                        next_chunk = min(chunk_size, hmac_start - current_pos)
                        
                        # Read chunk
                        chunk = in_file.read(next_chunk)
                        current_pos += len(chunk)
                        
                        # Update HMAC
                        h.update(chunk)
                        
                        # Decrypt chunk
                        decrypted_chunk = cipher.decrypt(chunk)
                        
                        # If this is the last chunk, remove padding
                        if current_pos >= hmac_start:
                            decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
                            
                        # Write to output file
                        out_file.write(decrypted_chunk)
                
                # Read and verify HMAC
                in_file.seek(hmac_start)
                received_hmac = in_file.read(32)
                
                try:
                    h.verify(received_hmac)
                    return True
                except ValueError:
                    # HMAC verification failed
                    # Delete the output file as it may be corrupt
                    os.remove(output_path)
                    return False
                    
        except Exception as e:
            # Handle decryption errors
            if os.path.exists(output_path):
                os.remove(output_path)
            return False