function AESDecrypt {
        param (
            [byte[]]$cipherData
        )
    
        $key = [Convert]::FromBase64String("saMQI5lVAircxR0AQaVuKrXq2HpT3zRGKQ0x/GO5/Fs=")
        $iv = [Convert]::FromBase64String("twlpLSWX5l15d6cxWDiwFg")
    
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
    
        $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
    
        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    
        $cryptoStream.Write($cipherData, 0, $cipherData.Length)
        $cryptoStream.Close()
    
        return $memoryStream.ToArray()
    }
    
    $cipherData = [System.IO.File]::ReadAllBytes(".\Ngggmyrptpi.pdf")
    $decryptedData = AESDecrypt -cipherData $cipherData
    [System.IO.File]::WriteAllBytes("decrypted.bin", $decryptedData)
}
