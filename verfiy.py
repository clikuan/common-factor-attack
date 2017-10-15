import Crypto
from Crypto.PublicKey import RSA


#Load public key back from file and we only need public key for encryption
with open('./publicKeys/public8.pub', 'r') as pub_file:
    pub_key = RSA.importKey(pub_file.read())

#Encrypt something with public key and print to console
encrypted = pub_key.encrypt(123456789, None) # the second param None here is useless
print(encrypted)

#Load private key back from file and we must need private key for decryption
with open('./private8.pem', 'r') as pvt_file:
    pvt_key = RSA.importKey(pvt_file.read())

#Decrypt the text back with private key and print to console
text = pvt_key.decrypt(encrypted)
print(text)