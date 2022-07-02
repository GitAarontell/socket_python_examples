import socket

# local host IP address
local_host = '127.0.0.1'

# used port 5000
port = 5000

data = b"HTTP/1.1 200 OK\r\n" \
       b"Content-Type: text/html; charset=UTF-8\r\n\r\n" \
       b"<html>Congratulations! You've downloaded the first Wireshark lab file!</html>\r\n"

# create the socket object with IPv4 and TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bound the socket to the localhost IP and port 5000
s.bind(('localhost', port))

# listening for connection with a queue of 0
s.listen(0)

# wait for a connection, when there is one, it returns the socket object and an array that has the IP address
# and the port address of the process that is connecting to this server
connection, address = s.accept()

# just prints the IP and port that the new socket is connected to
print('# connected to ' + address[0] + ':' + str(address[1]))

print('Received:\n')
# receives 5000 bytes of data from the client which is the get request
con_data = connection.recv(5000)

# prints the data but uses decoded to transform bytes to string
print(con_data.decode())

print('Sending>>>>>>>>\n')

# prints the data but uses decoded to transform bytes to string
print(data.decode())

# sends the client the byte data from the variable data above which is some html with header information
connection.send(data)
print('<<<<<<<<\n')

# closes the new socket connection
connection.close()

s.close()


