import binascii
import sys
import base64

state = [None] * 256
p = q = None

def setKey(key):
    global p, q, state
    state = [n for n in range(256)]
    p = q = j = 0
    for i in range(256):
        if len(key) > 0:
            j = (j + state[i] + key[i % len(key)]) % 256
        else:
            j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]

def byteGenerator():
    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    state[p], state[q] = state[q], state[p]
    return state[(state[p] + state[q]) % 256]

def decrypt(key, ct):
    return rc4(key, ct)

def rc4(key, ints):
    setKey(list(key))
    return [x ^ byteGenerator() for x in ints]

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <KEY> <Base64-Encoded-Payload>")
        sys.exit(1)
    key = sys.argv[1].encode()
    ciphertext = base64.decodebytes(sys.argv[2].encode())
    decrypted = decrypt(key, ciphertext)
    cleartext = ""
    for x in decrypted:
        cleartext += chr(x)
    print(cleartext)