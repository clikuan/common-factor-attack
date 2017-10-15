from Crypto.PublicKey import RSA
from base64 import b64decode
from fractions import gcd


def egcd(a, b):
	x,y, u,v = 0,1, 1,0
	while a != 0:
		q, r = b//a, b%a
		m, n = x-u*q, y-v*q
		b,a, x,y, u,v = a,r, u,v, m,n
	gcd = b
	return gcd, x, y


for i in range(1,13):
	filename1 = './publicKeys/public' + str(i) + '.pub'
	pub1 = open(filename1).read()
	keyPub1 = RSA.importKey(pub1)
	for j in range(i+1,13):	
		filename2 = './publicKeys/public' + str(j) + '.pub'
		pub2 = open(filename2).read()
		keyPub2 = RSA.importKey(pub2)
		gcdValue = gcd(keyPub1.n, keyPub2.n)
		if gcdValue != 1:
			print('Found: ' + filename1 + ' ' + filename2 + ' have gcd=(' + str(gcdValue) +')')
			print('Common factor attacks!')	
			print('')

			p1, q, p2, = keyPub1.n//gcdValue, gcdValue, keyPub2.n//gcdValue
			n1_phi, n2_phi = (p1-1)*(q-1), (p2-1)*(q-1)
			e1_inverse, e2_inverse = egcd(keyPub1.e, n1_phi)[1], egcd(keyPub2.e, n2_phi)[1]
			d1, d2 = e1_inverse % n1_phi, e2_inverse % n2_phi

			print('d1 = ' + str(d1))
			privateKey1 = RSA.construct((keyPub1.n, keyPub1.e, d1))
			f = open('private' + str(i) + '.pem','wb')
			f.write(privateKey1.exportKey('PEM'))
			f.close()

			print('')

			print('d2 = ' + str(d2))
			privateKey2 = RSA.construct((keyPub2.n, keyPub2.e, d2))
			f = open('private' + str(j) + '.pem','wb')
			f.write(privateKey2.exportKey('PEM'))
			f.close()
			
