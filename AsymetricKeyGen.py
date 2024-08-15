from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_asymmetric_keypair():
   # generate an RSA key pair
   private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=512,
      backend=default_backend()
   )
   # extract the public key
   public_key = private_key.public_key()
   # change keys to PEM format.
   private_key_pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
   )
   public_key_pem = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
   )
   return private_key_pem, public_key_pem

# generate an RSA key pair
private_key, public_key = generate_asymmetric_keypair()
print("Private Key:\n", private_key.decode())
print("Public Key:\n", public_key.decode())