import sys
import socket
import threading
import ast
from Crypto.Random import random
from utils import *


user_dict = {}

text_dict = {}


def handle_connection(conn, addr):

	global user_dict

	print 'Connected by', addr

	while 1:
		data = conn.recv(1024)

		(user, mtype, message) = ast.literal_eval(data)

		if mtype == USER_REG:
			print "User %s connected." %user
			user_dict[user] = conn

		elif mtype == USER_EXT:
			print "User %s disconnected." %user
			user_dict[user].close()
			del user_dict[user]
			return 

		elif mtype == GET_SALT:
			dest_user = message

			salt = random.getrandbits(plaintext_len)
			
			user_dict[dest_user].sendall( str( (user, SALT, salt ) ) )

			user_dict[user].sendall( str( (dest_user, SALT, salt ) ) )


		elif  mtype == FWD_TO:
			[ dest_user, enc ] = message


			if dest_user in user_dict:
				print "Forward message to user %s from %s." %(dest_user, user)

				user_dict[dest_user].sendall( str( (user, FIRST_STEP, [enc] ) ) )

			else:
				print "Cannot forward message to %s. User does not exist." %dest_user

		elif mtype == SECOND_STEP:
			[ dest_user, enc, new_plaintext ] = message
			print "Got return message from user %s to user %s" %(user, dest_user)
			
			# return to dest_user everything without the plaintext
			if dest_user not in text_dict:
				text_dict[dest_user] = {}

			text_dict[dest_user][user] = new_plaintext

			user_dict[dest_user].sendall( str( (user, SECOND_STEP, enc ) ) )

		elif mtype == FINAL:
			[dest_user , plaintext ] = message 
			print "Got final message from user %s regarding target %s" %(user, dest_user)

			#print "Expected message: ", text_dict[user][dest_user]
			#print "Got message: ", plaintext


			if plaintext == text_dict[user][dest_user]:
				print "Users %s and %s are near" %(user, dest_user)

				user_dict[user].sendall( str( (dest_user, FINAL, ARE_CLOSE ) ))

			else:
				print "Users %s and %s are far apart" %(user, dest_user)
			
				user_dict[user].sendall( str( (dest_user, FINAL, DISTANT ) ))

			del text_dict[user][dest_user]

			#send result back

		#print "Type received:", str( mtype )
		#print "Message:", str( message )

		#print user_dict

def main():

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((HOST, PORT))
	s.listen(10)

	while 1:
		conn, addr = s.accept()
		
		t = threading.Thread(target=handle_connection, args=(conn, addr))
		t.daemon = True
		t.start()
		


if __name__ == '__main__':
	main()