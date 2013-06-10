
def debug(data):
	if DEBUG == 1: print data


DEBUG = 0

plaintext_len = 256
HOST = '127.0.0.1'
PORT = 17171

GET_SALT = -2
SALT = -1
USER_REG = 0
USER_EXT = 1
FWD_TO = 2

FIRST_STEP = 3
SECOND_STEP = 4
FINAL = 5


ARE_CLOSE = 0
DISTANT = 1