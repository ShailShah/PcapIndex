import socket
import sys
from thread import *
from ip_addr import *
from mac_addr import *
from threading import Timer

ip_mac={}
ip_loc={}
ip_ttl={}

def remove_ip(conn,data):
	if data.split(" ")[1] in ip_mac:
		del ip_mac[data.split(" ")[1]]
		del ip_loc[data.split(" ")[1]]
		del ip_ttl[data.split(" ")[1]]
		reply="ok"
		conn.sendall(reply)
		print ip_mac
		print ip_loc
		print ip_ttl
		print data.split(" ")[1],"removed--------------------------------------"
		conn.close()
	else:
		reply="ok"
		conn.sendall(reply)
		conn.close()

	
def insert_ip(conn,data):
		ip_loc[data.split(" ")[1]]=(data.split(" ")[2])
		ip_mac[data.split(" ")[1]]=(data.split(" ")[3])
		ip_ttl[data.split(" ")[1]]=180
		start_new_thread(ttl,(data.split(" ")[1],))
		reply="ok"
		conn.sendall(reply)
		print ip_mac
		print ip_loc
		print ip_ttl
		print data.split(" ")[1],"inserted--------------------------------------"
		conn.close()

def keep_alive(conn,data):
	if data.split(" ")[1] in ip_mac:
		ip_ttl[data.split(" ")[1]]=ip_ttl[data.split(" ")[1]]+180
		start_new_thread(ttl,(data.split(" ")[1],))
		reply="ok"
		conn.sendall(reply)
		print data.split(" ")[1],"ttl updated"
		conn.close()
	else:
		reply="ok"
		print reply
		conn.sendall(reply)
		conn.close()

def ttl(ip):
	t=[]
	for i in range(5,185,5):
		o=Timer(i,minus_5,(ip,))
		t.append(o)
	
	for o in t:
		o.start() 

def minus_5(ip):
	if ip in ip_mac and ip in ip_loc and ip in ip_ttl:
		ip_ttl[ip]=ip_ttl[ip]-5
	else:
		sys.exit()
	
	if ip_ttl[ip]<=0:
		del ip_mac[ip]
		del ip_loc[ip]
		del ip_ttl[ip]
		print ip_mac
		print ip_loc
		print ip_ttl
		print "ttl removed--------------------------------------"


while 1:
	try:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		break
	except socket.error,msg:
		continue

print "Socket created"

host=S1
port=32000

while 1:
	try:
		s.bind((host,port))
		break
	except socket.error,msg:
		continue

print "Bind complete"

s.listen(50)

print "Socket listening"
print "--------------------------------------"

while 1:
	conn,addr=s.accept()
	data=conn.recv(4096)
	if (data.split(" ")[0]=="remove"):
		start_new_thread(remove_ip,(conn,data,))
	elif (data.split(" ")[0]=="insert"):
		start_new_thread(insert_ip,(conn,data,))
	elif (data.split(" ")[0]=="keepalive"):
		start_new_thread(keep_alive,(conn,data,))
	else:
		reply="Invalid messege"
		conn.sendall(reply)
		conn.close()
	
s.close()
