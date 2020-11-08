import socket

port = 53
ip = '127.0.0.1'
#DNS operates on port 53 by default

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((ip,port))


while 1:
    data,addr = sock.recvfrom(512)
    print(data)