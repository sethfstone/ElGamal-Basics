# ElGamal-Basics
This is a very simple implementation of an ElGamal command line tool. You can generate key pair, shared Diffie Hellman key, as well as sign and verify. This is not completely secure and not meant to be used - just wanted to delve into a bit of cryptography; hence, it is written in python.


    _______________________________________________________________________________________________________________

Insecurities:
    - private key information stored in plaintext
    - hash function isn't pre-image or collision resistant
    - may be susceptible to linear cryptanalysis
    
