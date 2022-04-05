import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# read RSA private key
private_key = RSA.import_key(open('private.pem').read())

# read encrypted data
with open('encrypted_data.txt', 'r') as f:
    encrypted_session_key = f.readline().split()[1]
    encrypted_session_key = base64.b64decode(encrypted_session_key)

    nonce = f.readline().split()[1]
    nonce = base64.b64decode(nonce)

    tag = f.readline().split()[1]
    tag = base64.b64decode(tag)

    ciphertext = f.readline().split()[1]
    ciphertext = base64.b64decode(ciphertext)

# use RSA key to decrypt AES session key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(encrypted_session_key)

# use AES session key to decrypt the data
cipherAES = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipherAES.decrypt_and_verify(ciphertext, tag)

# print the decrypted data
print(data.decode('utf-8'))
