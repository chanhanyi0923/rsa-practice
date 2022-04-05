import base64
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

data = b'Hello world'

# read RSA public key
public_key = RSA.import_key(open('public.pem').read())

# create AES Session key randomly
session_key = get_random_bytes(16)

# use RSA encrypt AES session key
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_session_key = cipher_rsa.encrypt(session_key)

# use AES Session key to encrypt data
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)

# write results to file
with open('encrypted_data.txt', 'w') as f:
    f.write('encrypted_session_key: ')
    f.write(base64.b64encode(encrypted_session_key).decode('utf-8'))
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