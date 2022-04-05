from Crypto.PublicKey import RSA

# generate RSA of 2048 bits
key = RSA.generate(2048)

# RSA private key
private_key = key.export_key()
with open('private.pem', 'wb') as f:
    f.write(private_key)

# RSA public key
public_key = key.publickey().export_key()
with open('public.pem', 'wb') as f:
    f.write(public_key)
