import base64
from Crypto.Cipher import AES

# read encrypted data
with open('encrypted_data.txt', 'r') as f:
    session_key = f.readline().split()[1]
    session_key = base64.b64decode(session_key)

    nonce = f.readline().split()[1]
    nonce = base64.b64decode(nonce)

    tag = f.readline().split()[1]
    tag = base64.b64decode(tag)

    ciphertext = f.readline().split()[1]
    ciphertext = base64.b64decode(ciphertext)

# use AES session key to decrypt the data
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

# print the decrypted data
print(data.decode('utf-8'))
