import socket
import time
from threading import Timer
from thread import *
from ip_addr import *
from mac_addr import *
from consistenthash import *

ip=["", "", "", ""]

last_pub=["", "", "", ""]

ch=HashRing([S1,S2,S3])

def hash_ip(ip):
	return ch.get_node(ip)


def remove_ip(ip,i):
	if ip=="":
		return
	else:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		print "Socket created for remove"
		
		host=hash_ip(ip)
		port=32000
		
		s.bind(("10.200.200.145",0))
		s.connect((host,port))

		#print "Connected to "+host+" at "+str(port)
		
		message="remove "+ip
		reply=""
				
		while reply!="ok":
			try:
				s.sendall(message)
				reply=s.recv(4069)
			except socket.error:
				continue
		print "Entry removed"
		last_pub[i]=""
		
			
def insert_ip(ip,i):
	if ip=="":
		return
	else:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		print "Socket created for insert"
		
		host=hash_ip(ip)
		port=32000
		
		s.connect((host,port))
		
		#print "Connected to "+host+" at "+str(port)
		
		message="insert "+ip+" "+mac[S1]+" "+mac[ip]
		reply=""
				
		while reply!="ok":
			try:
				s.sendall(message)
				#print "Message sent"
				reply=s.recv(4096)
			except socket.error:
				continue

		print "Entry inserted"
		
		last_pub[i]=ip
		
def keep_alive():
	while 1:
		for i in ip:
			if i!="":
				start_new_thread(send_ka,(i,))
		time.sleep(150)

def send_ka(i):
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	print "Socket created for keepalive"
	host=hash_ip(i)
	port=32000
	s.connect((host,port))
	#print "connected ka"
	message="keepalive "+i
	reply=""
	while reply!="ok":
		try:
			s.sendall(message)
			#print "Message sent ka",i
			reply=s.recv(4096)
		except socket.error:
			continue	
	print "Keepalive successfull"


def test_1():
	ip[0]=h1
	ip[1]=h2

def test_5():
	ip[0]=""

def test_8():
	ip[2]=h3

Timer(60,test_1,()).start()
Timer(300,test_5,()).start()
Timer(480,test_8,()).start()

start_new_thread(keep_alive,())

while 1:
	if ip[0]!=last_pub[0]:
		print "port 1"
		remove_ip(last_pub[0],0)
		insert_ip(ip[0],0)
	
	if ip[1]!=last_pub[1]:
		print "port 2"
		remove_ip(last_pub[1],1)
		insert_ip(ip[1],1)
	
	if ip[2]!=last_pub[2]:
		print "port 3"
		remove_ip(last_pub[2],2)
		insert_ip(ip[2],2)
		
	if ip[3]!=last_pub[3]:
		print "port 4"
		remove_ip(last_pub[3],3)
		insert_ip(ip[3],3)
	#time.sleep(10)
