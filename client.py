import sys
import socket
import ast
import threading
import binascii
import Crypto
import signal
import time
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import random
from utils import *


s = None
user = None
location = None
# location will be used as key 
#location = "44.445173,26.056056"

user_dict = {}
salts = {}
distance = 0

tstart = 0
tend = 0

def signal_handler(signal, frame):
	global s
	#print type(s)

	s.sendall( str( (user, USER_EXT, "") ) )
	s.close()
	print 'You pressed Ctrl+C!'

	sys.exit(0)

def get_hex(data):
	"""
	debug function used to print binary data to hex 
	"""

	return binascii.b2a_hex(data)


def get_location(r):
	"""
	this should provide the relative location of the client 
	"""

	x = float(location.split(",")[0])
	y = float(location.split(",")[1])


	u = int(x * 1000000 / r)
	v = int(y* 1000000 / r )


	return str(u)+","+str(v)

def get_key_from_data(data):
	"""
	TODO: add salt
	"""
	key = SHA256.new( data )

	debug( "Key: %s"  % key.hexdigest() )

	return key.digest()

def create_enc(salt, r):

	plaintext = random.getrandbits( plaintext_len )

	debug( "Plaintext: %s" %get_hex( random.long_to_bytes(plaintext) ))
	
	# 32 length key
	#salt = random.getrandbits(plaintext_len)
	

	key = get_key_from_data( random.long_to_bytes(salt) + get_location(r) )
	aes = AES.new( key )
	enc =  aes.encrypt( random.long_to_bytes(plaintext) ) 
	debug( "Encrypted: %s" % get_hex(enc) )


	return (plaintext, enc)


def wait_connection():

	global s 
	global tstart
	global tend
	global user

	global salts
	while 1:
		data = s.recv(1024)

		(dest_user, mtype, emessage) = ast.literal_eval(data)

		if mtype == SALT:

			print "Received salt: ", get_hex(random.long_to_bytes(emessage))

			salts[dest_user] = emessage


		elif mtype == FIRST_STEP:

			[r, enc_message] = emessage

			key = get_key_from_data( random.long_to_bytes(salts[dest_user]) + get_location(r) )
			aes = AES.new( key )
			message = aes.decrypt(enc_message)

			del salts[dest_user]

			debug( "Decrypted: %s" % get_hex( message ) )
			

			new_key = SHA256.new( message ).digest()

			debug( "New key: %s"  %get_hex(new_key) )
			new_plaintext = random.getrandbits( plaintext_len )
			debug("New plaintext: %s" % get_hex( random.long_to_bytes(new_plaintext) ) )
			aes = AES.new( new_key )

			enc = aes.encrypt(random.long_to_bytes(new_plaintext))

			debug( "New Encrypted: %s" % get_hex(enc) )
			message = [ dest_user, enc, random.long_to_bytes(new_plaintext) ]

			s.sendall( str(  (user, SECOND_STEP, message) ))

		elif mtype == SECOND_STEP:

			del salts[dest_user]
			
			aes = AES.new( user_dict[dest_user] )

			debug( "Received text to decrypt: %s" %get_hex(emessage) )

			result = aes.decrypt(emessage)

			debug( "Decoded: %s" %get_hex(result) )

			message = [ dest_user, result ]
			s.sendall( str( (user, FINAL, message)) )

		elif mtype == FINAL:

			tend = datetime.now()

			

			print tend - tstart
			print "I am user %s " %user
			

			if emessage == ARE_CLOSE:
				print "User %s is somewhere nearby." %dest_user
			elif emessage == DISTANT:
				print "User %s is at an unknown location." %dest_user
			else:
				print "Error in message received."

	return 

def main():


	global tstart
	global tend
	signal.signal(signal.SIGINT, signal_handler)
	

	global s
	global user_dict
	global user
	global location
	global distance

	user = raw_input("Enter your username: ")
	

	while 1 == 1:

		location = raw_input("Enter your location: ")

		try:
			x = float(location.split(",")[0])
			y = float(location.split(",")[1])
			break
		except:
			print "[ERR] Formatul trebuie sa fie de forma: X,Y"
			print "[ERR] Unde X si Y sunt coordonate geografice"
			continue


	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((HOST, PORT))
	s.sendall( str( (user, USER_REG, "") ) )
	

	t = threading.Thread(target=wait_connection, args = ( ) )
	t.daemon=True
	t.start()


	distance = int( raw_input("Distanta de cautare: ") )
	
	while 1:

		


		dest_user = raw_input("Trimite catre user: ")
		tstart = datetime.now()

		if dest_user:

			s.sendall( str((user, GET_SALT, dest_user)))

			while dest_user not in salts:
				time.sleep(0.5)

			(plaintext, enc) = create_enc( salts[dest_user], distance)

			user_dict[ dest_user ] = get_key_from_data( random.long_to_bytes(plaintext) )

			message = [dest_user, distance, enc]

			s.sendall( str( (user, FWD_TO, message) ) )

			


		continue

	signal.pause()

if __name__ == '__main__':
	main()
