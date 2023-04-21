import sys, random, hashlib, pathvalidate
from math import gcd

#General err method
def genErr():
	print("\nPlease choose an option by adding arguments:\n[0] option choice (encrypt, decrypt, sign, verify, keygen, diffie)\n\tEncrypt:\n\t[1] message (int form)\n\t\t[2] prime\n\t\t\t[3] public key\n\tDecrypt:\n\t[1] ciphertext\n\t\t[2] prime\n\t\t\t[3] public u\n\t\t\t\t[4] private key\n\tSign:\n\t[1] message (int form)\n\t\t[2] prime\n\t\t\t[3] private key\n\tVerify:\n\t[1] signature\n\t\t[2] public key\n\t\t\t[3] message (hash)\n\t\t\t\t[4] prime\n\t\t\t\t\t[5] u\n\tDiffie:\n\t[1] prime\n\t\t[2] public key\n\t\t\t[3] private key\n") 
	print("\n\t-If your filename has a space in it make sure to add \"\" around it\n")
	return


#Checks for primality using Fermats primality test 
def isPrime(p, k):
	if p == 1 or p == 4:
		return False
	elif p == 2 or p == 3:
		return True
	else:
		for i in range(k):
			a = random.randint(2, p - 2)
			if pow(a, p - 1, p) != 1:
				return False
	return True


#Generates random prime numbers
def generatePrime(bitlength):
	temp = random.getrandbits(bitlength)

	while(temp):
		if(temp % 2 == 0):
			temp = random.getrandbits(bitlength)
		else:
			if(isPrime(temp, 5)): return temp
			else: temp += 2	

#Generate key
def generateKeyPair():
	bitlength = 2048
	p = 31749686553962123830150390511899406233318147926192054924173247225984942610607085898036236597579168656508141544444947451640437305445865004023831690316812119238221660935808050710465962663773794580227321449640813797371675353086915110192492102165066079858606044205020298397219959249401588688824077601119920485694595588897635990767924207829692866428388759879635463167667548725842887833414272954874062242400102665206437807289773494426284773182868846487610295502531467808247076749468875824653811747347455084341774558170285779742313215159336451809958079856055997491418717735631848236659778766077968208866837864962631819501613
	g = 2

	print("prime", p)

	privateKey = generatePrivate(p)
	print("\nPrivate Key Chosen:\n", privateKey)

	publicKey = pow(g, privateKey, p)
	print("\nPublic Key Computed:\n", publicKey)

	file = "publickeyinfo.txt"

	while(1):
		try:
			filename = open(file, "x")
			if(file != ""): break
		except:
			print("\nFile with that name already exists.")
			file = input("Please enter a new name (without file type): ")
			file = pathvalidate.sanitize_filename(file)
			file = file + ".txt"



	filename.write("-----Public Key-----")
	filename.write("\n{ ")
	filename.write(str(publicKey))
	filename.write(" }\n")
	filename.write("-----Public Prime----")	
	filename.write("\n{ ")
	filename.write(str(p))
	filename.write(" }\n")

	file = "privatekeyinfo.txt"

	while(1):
		try:
			filename = open(file, "x")
			if(file != ""): break
		except:
			print("\nFile with that name already exists.")
			file = input("Please enter a new name (without file type): ")
			file = pathvalidate.sanitize_filename(file)
			file = file + ".txt"



	filename.write("-----Private Key-----")
	filename.write("\n{ ")
	filename.write(str(privateKey))
	filename.write(" }\n")



	return [privateKey, publicKey, p]

#Encryption 
def encrypt(message, prime, publicKey, generator):
	message = int(message)

	print("msg", message)

	k = generatePrivate(prime)

	u = pow(generator, k, prime)
	build = pow(publicKey, k, prime)

	print("u\n", u)
	print("\npublicKey^k mod prime\n", build)

	ciphertext = int(message)*build % prime
	print("\nciphertext:\n", ciphertext)

	file = "cipher-out.txt"

	while(1):
		try:
			filename = open(file, "x")
			if(file != ""): break
		except:
			print("\nFile with that name already exists.")
			file = input("Please enter a new name (without file type): ")
			file = pathvalidate.sanitize_filename(file)
			file = file + ".txt"



	filename.write("-----Ciphertext-----\n")
	filename.write(str(ciphertext))
	filename.write("\n-----Public Portion-----\n")
	filename.write(str(u))

	return [ciphertext, u]

#Decryption 
def decrypt(ciphertext, prime, publicU, privateKey):
	ciphertext = int(ciphertext)

	x = pow(publicU, privateKey, prime)

	build = pow(x, -1, prime)
	plaintext = ciphertext*build % prime
	print("\nplaintext:\n", plaintext)

	file = "plaintext.txt"

	while(1):
		try:
			filename = open(file, "x")
			if(file != ""): break
		except:
			print("\nFile with that name already exists.")
			file = input("Please enter a new name (without file type): ")
			file = pathvalidate.sanitize_filename(file)
			file = file + ".txt"



	filename.write("-----Plaintext-----\n")
	filename.write(str(plaintext))
	filename.write("\n")

	return [plaintext]


#Computing signature
def sign(message, prime, privateKey, generator):
	print("messsage", message, type(message))
	print("prime", prime, type(prime))
	print("privateKey", privateKey, type(privateKey))
	print("generator", generator, type(generator))

	hashedMsg = hashlib.md5()
	hashedMsg.update(message.encode())
	hashedMsg = hashedMsg.hexdigest()
	hashedMsg = int(hashedMsg, 16)
	print("hashedMsg", hashedMsg, type(hashedMsg))

	k = generateRelativePrivate(prime)
	print("\nk", k)

	u = pow(generator, k, prime)
	print("\nu", u)

	signature = ((hashedMsg - privateKey*u) * pow(k, -1, prime - 1)) % (prime - 1)
	print("\nsignature", signature)

	return [u, k, signature]





#Verifying
def verify(signature, publicKey, hashed, prime, u, generator):
	print("signature", signature, type(signature))
	print("publicKey", publicKey, type(publicKey))
	print("prime", prime, type(prime))
	print("u", u, type(u))

	#testing
	hashedMsg = hashed

	left = pow(pow(publicKey, u, prime)*pow(u, signature, prime), 1, prime)
	print("\nleft", left)

	right = pow(generator, hashedMsg, prime)
	print("\nright", right)

	if(left == right): 
		print("\nSignature passed")
		return True
	print("\nSignature failed")
	return False


#Diffie Hellman
def diffieHellman(generator, prime, publicKey, privateKey):
	print("prime", prime, type(prime))
	print("pubkey", publicKey, type(publicKey))
	print("privkey", privateKey, type(privateKey))
	
	sharedKey = pow(publicKey, privateKey, prime)
	print("\nshared key", sharedKey)

	return sharedKey



#Helper methods
def generatePrivate(prime):
	key = random.randint(int(pow(10,20)), int(prime))
	while gcd(key, int(prime)) != 1:
		key = random.randint(pow(10,20), int(prime))

	return key

def generateRelativePrivate(prime):
	key = random.randint(2, int(prime))
	while gcd(key, int(prime) - 1) != 1:
		key = random.randint(2, int(prime))

	return key



def main():
	#Main menu needs to have the following options:
		# encrypt, decrypt, sign, verify	
	try:
		option = sys.argv[1].lower()
	except IndexError:
			genErr()
			return

	match option:
		case "encrypt":
			try:
				message = sys.argv[2]
				prime = int(sys.argv[3])
				publicKey = int(sys.argv[4])

			except IndexError:
				genErr()
				return

			encrypt(message, int(prime), publicKey, 2)


		case "decrypt":
			try:
				ciphertext = sys.argv[2]
				prime = int(sys.argv[3])
				publicU = int(sys.argv[4])
				privateKey = int(sys.argv[5])

			except IndexError:
				genErr()
				return

			decrypt(ciphertext, prime, publicU, privateKey)

		case "sign":
			try:
				message = sys.argv[2]
				prime = sys.argv[3]
				privateKey = sys.argv[4]

			except IndexError:
				genErr()
				return

			sign(message, int(prime), int(privateKey), 2)


		case "verify":
			try:
				signature = sys.argv[2]
				publicKey = sys.argv[3]
				hashed = sys.argv[4]
				prime = sys.argv[5]
				u = sys.argv[6]

			except IndexError:
				genErr()
				return

			res = verify(int(signature), int(publicKey), int(hashed), int(prime), int(u), 2)
			print("\nVerification result: ", res)

		case "keygen":
			#Generates key by choosing random number in Zp* (mult. group) 
			#and computes u = pow(gen, randomnum, mod p) and C = Plaintext()
			generateKeyPair()

		case "diffie":
			try:
				prime = sys.argv[2]
				publicKey = sys.argv[3]
				privateKey = sys.argv[4]

			except IndexError:
				genErr()
				return


			diffieHellman(2, int(prime), int(publicKey), int(privateKey))

		case "":
			genErr()

if __name__ == "__main__":
	main()