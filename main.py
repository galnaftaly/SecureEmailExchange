# -*- coding: utf-8 -*-
"""
Created on Wed May 18  19:35:08 2022

@authors: Eden, Aviv, Gal, Michael

Blowfish encryption using RSA async encryption and El-Gamal Signature scheme.
"""

import sys
import rsa
import elgamal 
import blowfish
from hashlib import sha256                                      #import hash function
from random import randint


N = 64                                                         # N would be the key size
hush_func = sha256()                                           #save hash function

#Create El-Gamal system and generate keys                 
alice_el_gamal = elgamal.generate_system(N, hush_func)
bob_el_gamal = elgamal.generate_system(N, hush_func)

#generate integer pair (private, public) of private and public keys 
alice_sig_keys=elgamal.generate_keys(alice_el_gamal)  
bob_sig_keys=elgamal.generate_keys(bob_el_gamal)

print('El-Gamal signature system has been delivered securely by both Alice and Bob.')
print('Alice and Bob will now be able to validate each other signatures.\n\n')


#Alice performs RSA delivery
primeSize = 512
p = rsa.getRandomPrime(primeSize)
q = rsa.getRandomPrime(primeSize)
while p == q:                           # for safety reasons make sure p and q are'nt the same
    q = rsa.getRandomPrime(primeSize)
n, e, d = rsa.getKeys(p, q)

# public key = (n,e)
print("RSA public key has been sent to Bob \n n = {} \ne = {} \n".format(n,e))
print("Sending signature to Bob\n")

RSAPublicKeysSignature = elgamal.sign(alice_el_gamal,str(hash(str(n+e))),alice_sig_keys[0])
print("Sent RSA public key signature = {}\n".format(RSAPublicKeysSignature))


print('The message has been delivered successfully to Bob/n')
print('Bob performs the validation process\n')

#check if the condition has been met
if(elgamal.verify(alice_el_gamal,str(hash(str(n+e))) , RSAPublicKeysSignature,alice_sig_keys[1])):
    print('The signature has been verified, message was sent by Alice')
else:
    print('Operation has been compromised! Run for your life!!!')
    sys.exit(0)
    

print("Bob generating random symmetric key of size between 32 to 448 bits (Blowfish possible key size)")
k =randint(pow(2,32),pow(2,448)-1)
while k%2==0:
    k =randint(pow(2,32),pow(2,448)-1)
print("Generated key is ",k)
print("\nBob encrypts the generated key\n")
encryptedKey=pow(k,e,n)
print("The encrypted Key is ",encryptedKey ,"\n")
KeySignature=elgamal.sign(bob_el_gamal,str(hash(str(k))),bob_sig_keys[0])

print("Bob signed on the hash of the original key.\nSignature is: ",KeySignature,"\nBob sends the encrypted key and the signature to Alice\n")

print("Alice now decrypts the key in order to verify it was sent by Bob\n")
decryptedKey=pow(encryptedKey,d,n)
if(elgamal.verify(bob_el_gamal,str(hash(str(decryptedKey))),KeySignature,bob_sig_keys[1]) and decryptedKey==k):
    print("Alice successfully verified that Bob sent the message, and they now share symmetric key.")
else:
    print('Operation has been compromised! Run for your life!!!')
    sys.exit(0)
    

print("Bob generates an IV for blowfish.\n")
iv=randint(2,pow(2,64)-1) # generate random IV
bytes_iv=iv.to_bytes(8,byteorder='big')
print("Bob now signs the generated IV's hash.\n")
ivSignature=elgamal.sign(bob_el_gamal,str(hash(str(iv))),bob_sig_keys[0])
encryptedIV=pow(iv,e,n)
print("Bob encrypts the IV using RSA Encryption and sends it with the signature to Alice.")

print("Alice received the encrypted data and signaure, and attempts to decrypt the data and verify it.\n")
decryptedIV=pow(encryptedIV,d,n)
if(elgamal.verify(bob_el_gamal,str(hash(str(decryptedIV))),ivSignature,bob_sig_keys[1])):
    print("Alice has verified the IV's data was sent by Bob.\n")
else:
    print('Operation has been compromised! Run for your life!!!')
    sys.exit(0)


blowfishKey=k.to_bytes(56,byteorder='big')

email=input("Please enter your mail text:\n")
length=len(email)%8
if(length!= 0): # pad the email in order to encrypt it
    email=email+" "*(8-length)


blowfishSystem=blowfish.Cipher(blowfishKey)

#Bob writes an email,encrypts and signs it then sends to Alice
print("Bob signs the email and encrypts it's content using blowfish.")
encryptedEmail=blowfishSystem.encrypt_cbc(str.encode(email),bytes_iv)
emailSignature=elgamal.sign(bob_el_gamal,str(hash(email)),bob_sig_keys[0])
encryptedEmail=b"".join(encryptedEmail)

print("Bob sent the following encrypted email and signature to Alice: ",encryptedEmail)
print("\nSignature:\n",emailSignature,"\n")
print("Alice received the email, decrypts it and validates if Bob was the sender.\n")
bytes_decryptedIV=decryptedIV.to_bytes(8,byteorder='big')
decryptedEmail=blowfishSystem.decrypt_cbc(encryptedEmail,bytes_decryptedIV)
decryptedEmail=b"".join(decryptedEmail).decode()
if(elgamal.verify(bob_el_gamal,str(hash(decryptedEmail)),emailSignature,bob_sig_keys[1])):
    print("Alice concludes that the email was sent by bob.\n")
else:
    print('Operation has been compromised! Run for your life!!!')
    sys.exit(0)

print("Decrypted email content is:\n",decryptedEmail)