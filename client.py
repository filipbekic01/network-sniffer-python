import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 1234))
print 'Say something: '
s.send("Server ce ovu recenicu zaokruziti crticama i vratiti mi kao takav response :P")
data = s.recv(4096)
s.close()
print data