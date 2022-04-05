import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

data = b'Hello world'

# create AES Session key randomly
session_key = get_random_bytes(16)

# use AES Session key to encrypt data
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)

# write results to file
with open('encrypted_data.txt', 'w') as f:
    f.write('session_key: ')
    f.write(base64.b64encode(session_key).decode('utf-8'))
    f.write('\n')

    f.write('nonce: ')
    f.write(base64.b64encode(cipher_aes.nonce).decode('utf-8'))
    f.write('\n')

    f.write('tag: ')
    f.write(base64.b64encode(tag).decode('utf-8'))
    f.write('\n')

    f.write('ciphertext: ')
    f.write(base64.b64encode(ciphertext).decode('utf-8'))
    f.write('\n')