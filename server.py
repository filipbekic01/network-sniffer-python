import socket
import sys

# Create a TCP/IP socket to listen on
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Prevent from "addres already in use" upon server restart
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket ot port 1234 on all interfaces
server_address = ('localhost', 1234)
server.bind(server_address)

# Liste for connections
server.listen(5)

# Wait for one incoming connection
connection, client_address = server.accept()
print 'Connection from ', connection.getpeername()

# Let's receive something
data = connection.recv(4096)

# Send it back nicely formatted
if data:
    print repr(data)
    data = data.rstrip()
    connection.send("%s\n%s\n%s\n" % ('-'*80, data.center(80), '-'*80))
    print 'Response sent!'

# Close the connection form our side
connection.shutdown(socket.SHUT_RD | socket.SHUT_WR)
connection.close()
print 'Connection closed.'

# And stop listening
server.close()

