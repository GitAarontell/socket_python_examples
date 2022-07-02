import socket

# socket.AF_INET is IPv4 and socket.SOCK_STREAM is TCP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connects to server and that server accepts the connection and waits to recieve data
s.connect(('gaia.cs.umass.edu', 80))

# client sending get request to server, the b is to make it bytes
s.send(b'GET /wireshark-labs/HTTP-wireshark-file3.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n')

# initial set up of response which will be all the data we receive from the server
response = b''

# client continues to receive until we break out of while loop
while 1:
    # received will be the data we get up to 100 bytes each time
    received = s.recv(100)

    # if client receives nothing, this will mean that the server is done sending
    # and so the length of the received will be 0
    if len(received) == 0:
        # if it is zero we break out of loop
        break
    # if not zero, then we continue to concatenate data received onto the response string
    response += received

# close the connection
s.close()

# print out what the data
print(response)
