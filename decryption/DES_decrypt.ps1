function Decrypt-DES {
        param (
            [string]$encryptedText,
            [string]$keyString
        )
    
        try {
            # Create an MD5 hash of the key
            $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
            $keyBytes = [System.Text.Encoding]::ASCII.GetBytes($keyString)
            $hash = $md5.ComputeHash($keyBytes)
    
            # Use first 8 bytes as the DES key
            $desKey = $hash[0..7]
    
            # Setup DES decryption
            $des = [System.Security.Cryptography.DESCryptoServiceProvider]::new()
            $des.Key = $desKey
            $des.Mode = [System.Security.Cryptography.CipherMode]::ECB
    
            # Create decryptor
            $decryptor = $des.CreateDecryptor()
    
            # Decode the Base64 encrypted string
            $encryptedBytes = [Convert]::FromBase64String($encryptedText)
    
            # Decrypt the data
            $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    
            # Convert the decrypted bytes back to string
            $decryptedText = [System.Text.Encoding]::ASCII.GetString($decryptedBytes)
    
            return $decryptedText
        } catch {
            Write-Error "Decryption failed: $_"
            return $null
        }
    }
    
    $result = Decrypt-DES -encryptedText "<ENCRYPTED_B64>" -keyString "<KEY_MATERIAL_B64>"
    if ($result) {
        Write-Output "Decrypted result: $result"
    } else {
        Write-Output "Decryption failed."
    }
}
