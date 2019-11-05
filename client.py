import socket
import random
import pyaes
from pbkdf2 import PBKDF2
from sys import argv
rutoeng = {'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y', 'г': 'u', 'ш': 'i','щ': 'o', 'з': 'p', 'х': '[', 'ъ': ']', 'ф': 'a', 'ы': 's', 'в': 'd', 'а': 'f','п': 'g', 'р': 'h', 'о': 'j', 'л': 'k', 'д': 'l', 'ж': ';', 'э': "'", 'я': 'z','ч': 'x', 'с': 'c', 'м': 'v', 'и': 'b', 'т': 'n', 'ь': 'm', 'б': ',', 'ю': '.'}
targetip = "0.0.0.0"
port = 4096
def escape(text):
	tor = ""
	cyrIdx = []
	m = 0
	res = ""
	for i in text:
		if i in rutoeng.keys():
			cyrIdx.append(m)
			tor += rutoeng[i]
		elif i.lower() in rutoeng.keys():
			cyrIdx.append(m)
			tor += rutoeng[i.lower()].upper()
		else:
			tor += i
		m = m + 1
	for i in cyrIdx:
		res += "|" + str(i)
	return (res, tor)
if len(argv) == 3:
	targetip = argv[1]
	port = int(argv[2])
elif len(argv) == 2:
	targetip = argv[1]
else:
	targetip = input("IP address to connect: ")
	port = int(input("Port to connect: "))
conn = socket.socket()
conn.connect((targetip, port))
hasKeySent = False
auth = False
secretKey = b'nothing'
while not hasKeySent:
	data = conn.recv(10000).decode("utf-8") # read public keys
	c = random.randint(1e97, 9.99e150) # make private key
	if "DHGPS " in data: # if server has sent auth header then
		auth = True
		data = data[6:].split(":") # define keys 
		g = int(data[0])
		p = int(data[1])
		S = int(data[2])
		C = pow(g, c, p) # make own public key...
		authhead = "DHC " + str(C)
		conn.send(authhead.encode()) # ... and send it to server because it will make a secret key for itself
		secretKey = PBKDF2(str(pow(S, c, p)), "msgdforever") # count secret key for encrypting, server already knows it
		hasKeySent = True
while not auth:
	if conn.recv(1024) == b"ASUC":
		auth = True
		print("Auth successfuly")
aes = pyaes.AESModeOfOperationCTR(secretKey.read(32))
while True:
	try:
		msg = input("MSG> ")
		escaped = escape(msg)
		if msg =="FILETYPE":
			inp = input("Do you want to send file? [y/n]")
			if inp == 'y':
				file = None
				try:
					file = open("uploads\\" + input("Path to file in uploads\\: "), 'rb')
				except:
					print("ERROR: File on this path doesn't exist")
					continue
				filedata = file.read()
				file.close()
				filename = input("What is name of the file (13symbols): ")
				filerequest = b"FILETYPE " + bytes(filename.encode()) + filedata
				encrypted = aes.encrypt(filerequest)
				print("File data encrypted")
				conn.send(encrypted)
				continue
		msg = escaped[0] + "\n" + escaped[1]
		crypted = aes.encrypt(msg)
		conn.send(crypted)
	except:
		socket.close()
		print("Connection closed by server host")
		break