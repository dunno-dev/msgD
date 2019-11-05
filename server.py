import socket
import threading
import random
import pyaes
import os
from pbkdf2 import PBKDF2
print("[+] MSG server 1.0A: STARTED")
engtoru = {'q': 'й', 'w': 'ц', 'e': 'у', 'r': 'к', 't': 'е', 'y': 'н', 'u': 'г', 'i': 'ш', 'o': 'щ', 'p': 'з', '[': 'х', ']': 'ъ', 'a': 'ф', 's': 'ы', 'd': 'в', 'f': 'а', 'g': 'п', 'h': 'р', 'j': 'о', 'k': 'л', 'l': 'д', ';': 'ж', "'": 'э', 'z': 'я', 'x': 'ч', 'c': 'с', 'v': 'м', 'b': 'и', 'n': 'т', 'm': 'ь', ',': 'б', '.': 'ю'}
def parse(escaped): # function to display cyrrilic correct
	m = 0
	cptext = list(escaped[1])
	cyrIdx = []
	tor = ""
	for i in escaped[0].split("|")[1:]:
		cyrIdx.append(int(i))
	for i in cptext:
		if m in cyrIdx:
			if i in engtoru.keys():
				cptext[m] = engtoru[i]
			else:
				cptext[m] = engtoru[i.lower()].upper()
		else:
			cptext[m] = i
		m += 1
	for i in cptext: tor += i
	return tor
def handle(connect, info): # function for threading
	print("New connection from: %s:%d" % (info[0], info[1]))
	g = random.randint(1, 30) # DH exchange; DH g
	p = random.randint(1e250, 9e300) # DH p
	s = random.randint(1e97, 9.99e150) # my secret
	print("NUMS GENERATED")
	S = pow(g, s, p) # my public
	crypthead = 'DHGPS %d:%d:%d' % (g, p, S)
	connect.send(bytes(crypthead.encode())) # send my public to client. He'll do pow(S, hissecret, p) (it is encrypt key)
	print("Public keys sent")
	isEncrypted = False
	C = 0
	secretKey = 0
	while not isEncrypted: # repeat until client won't send correct header
		try:
			gotauth = connect.recv(1024).decode("utf-8") # read request
			if 'DHC' in gotauth: # if it is right header in it
				isEncrypted = True # end this loop
				C = int(gotauth[4:]) # read his public key
				connect.send(b'ASUC')
				secretKey = PBKDF2(str(pow(C, s, p)), "msgdforever") # generate main key for encryption
		except:
			connect.close() # if any exceptions close connection
			print("Conection closed before client auth")
			return
	aes = pyaes.AESModeOfOperationCTR(secretKey.read(32)) # generating AES-256 pattern
	while True:
		try:
			got = connect.recv(100000000) # gotten array of encrypted bytes
			predecrypt = aes.decrypt(got) # decrypted array of bytes 
			if predecrypt[:8].decode('utf-8') == "FILETYPE": # if it consists header FILETYPE
				filename = predecrypt[9:22].decode('utf-8') # decoding name of income file
				inp = input("Do you want to save file " + filename + "? [y/otherletter]") # ask user
				if inp == 'y':
					f = open('downloads\\' + filename, 'wb') # create a new file (or rewrite old one)
					f.write(predecrypt[19:]) # write decrypted content of the file
					f.close() # close file stream
					print("File downloaded to downloads/")
					if input("Execute that file? \n [Make sure its not a virus.] [y/otherletter]") == 'y': 
						os.system(os.path.dirname(os.path.abspath(__file__)) + "\\downloads\\" + filename) # execute file by standard tool for it.
					continue # skip iteration
			decrypted = predecrypt.decode("utf-8").split('\n') # non-escaped decrypted message
			
			decrypted = parse(decrypted)
			print("From " + info[0] + ":" + decrypted) # printing decrypted data of request
		except: # if got error or client has closed connection: 
			connect.close() 		#1. close it
			print("Connection closed")
			return					#2. end client handler because socket has closed
config = open("msg.conf").read().split("@")
port = int(config[1]) # port for messaging
localip = config[0] # local ip of host computer (server)
sock = socket.socket() 
server = sock.bind((localip, port))
sock.listen(10) 
print("[+] MSG server 1.0A: INIATILIZATED")
try:
	while True: 
		conn, addr = sock.accept() # income connection
		try:
			handler = threading.Thread(target=handle, args=(conn, addr)) # starting a handler for client like a new Thread
			handler.start()
		finally: pass # python3 bug
finally: sock.close() # anyway closing server socket