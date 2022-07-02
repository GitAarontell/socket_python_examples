import socket

# socket.AF_INET is IPv4 and socket.SCOK_STREAM is TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connects to server and that server accepts the connection and waits to receive data
s.connect(('gaia.cs.umass.edu', 80))

# client sending get request to server
s.send(b'GET /wireshark-labs/INTRO-wireshark-file1.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n')

# client gets servers response up to 4000 bytes and stores it in response variable
response = s.recv(4000)

# close the connection
s.close()

# print out what the data was
print(response)