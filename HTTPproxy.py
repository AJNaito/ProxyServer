# Place your imports here
import signal
import sys
import threading
from socket import *
from optparse import OptionParser

#Cache is disabled as a default
cacheEnabled = False
cache = {}
cacheMethods = ["enable", "disable", "flush"]
lockCache = threading.Lock()

#blocklist is enabled as default
blockListEnabled = True
blockList = {}
blocklistMethods = ["enable", "disable", "flush", "add", "remove"]
lockBL = threading.Lock()

# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
	sys.exit(0)

# Read the client request
def read_request(socket):
     #initialize data
     data = ""

     #go while we still have a valid socket or we reach the end of the request line
     while (socket and ("\r\n\r\n" not in data)):
        raw_bytes = socket.recv(4096)
        if (raw_bytes):
            data += decode_bytes(raw_bytes)
        else:
            return data
        
     return data

### Not all information obtained from the client is decodable
def decode_bytes(bytes):
    try:
        # attempt to decode the bytes
        decoded = bytes.decode('utf-8')

        # code can't detect normal \r\n
        decoded = decoded.replace("\\r\\n", "\r\n")
        return decoded
    except:
        return ''
    
### This method makes an error_message to be sent back to the client
def error_message(client_socket, status):
    ## HTTP version is 1.0
    message = "HTTP/1.0 " + str(status) + ' '

    # put the extra message into the error_message
    if (status == 400):
        message += "Bad Request"
    if (status == 501):
        message += "Not Implemented"
    if (status == 403):
        message += "Forbidden"
    
    message += "\r\n\r\n"
    
    client_socket.send(message.encode())

### read the full request from the client
def parse_request(raw_data, dictionary):
     # split the raw_data by line
     lines = raw_data.split("\r\n")
    
     # find the method line
     method_line = lines[0]
     for line in lines:
         if (line.startswith("GET")):
             method_line = line

     #first line should be method - get the method and places it into dictionary
     if(parse_method(dictionary, method_line.rstrip()) is False):
        return 400

     # read the rest of the headers - pputs the headers into the dictionary
     if (parse_headers(dictionary, lines[1:]) is False):
        return 400
     
     #validate that request
     return valid_request(dictionary)

### This method identifies any headers that should be included in the msg to the server
def parse_headers(dict, lines):
     for line in lines:
         #no white space
         line = line.rstrip()

         #don't process empty lines
         if (line == ""):
             continue

         elements = line.split(" ")
         
         # Headers will always end with ':'
         if (elements[0].endswith(":")):
             if (elements[0].startswith("Host")):
                 #found host -- Must match to the hostname given
                 host = dict.get("Host:")

                 if (host != elements[0]):
                     return False
             else:
                # adds the other headers
                dict.update({elements[0]: " ".join(elements[1:])})
         else:
             return False
         
     return True

### This method splits and separates hostname, port, and the path from the request line
def parse_method(dict, line):
     elements = line.rstrip().split(" ")

     if (len(elements) != 3):
        return False
     
     if (elements[1].startswith("http://")):
         url = elements[1].replace("http://", "")
         if (not "/" in url):
             return False
         
         ## create a full and valid host to put in dict
         parts = url.split("/")
         url = ""
         host_port = parts[0].split(":")
         if (not host_port[0].startswith("www") and not host_port[0].startswith("localhost")):
             url = "www." + host_port[0]
         else:
             url += host_port[0]
         dict.update({"Host:": url})
         
         # port defauled to 80 if no specified port
         dict.update({"Port:": "80"})
         if (len(host_port) == 2):
             dict.update({"Port:": host_port[1]})

         # constructs the path
         path = ""
         for x in parts[1:]:
             path += '/' + str(x)

         if (len(path) == 0):
             path = "/"

         dict.update({"Path:": path})
     else:
         # URL isn't formed properly
         return False

     dict.update({"Method:": elements[0]})
     dict.update({"Version:": elements[2]})
     return True
        
### validates the request
def valid_request(dictionary):
    method_name = dictionary.get('Method:')
    if (method_name is not None) :
        #method entry
        if (method_name != 'GET'):
            valid_methods = ["HEAD", "POST", "REMOVE", "OPTIONS"]
            if (method_name in valid_methods):
                return 501
            return 400

    # Get the version type (should be HTTP/1.0)
    version_type = dictionary.get('Version:')
    if (version_type is not None):
        #version entry
        if (version_type != "HTTP/1.0"):
            return 400
    
    # GEt the host and path from dictionary
    if (dictionary.get('Host:') is None and dictionary.get('Path:') is None):
        #no valid path and/or host
        return 400
    
    # no problems detected
    return 200

### Read the response from the server
### Returns (header bytes, body bytes)
def read_response(socket):
    raw_bytes = b""
    header_div = b"\r\n\r\n"

    ## reads the response -- just checks for the header
    while (socket and header_div not in raw_bytes):
        raw_bytes += socket.recv(4096)

    # split the bytes by the header/body (no guarantee that I don't read body bytes)
    bytes = raw_bytes.split(header_div)
    
    # return header and body
    return (bytes[0], bytes[1])

### Parse and reads the rest the response from the server
def parse_response(header, body, socket):
    # Read the header bytes
    h_string = decode_bytes(header)

    lines = h_string.split("\r\n")
    body_bytes = 0
    date = ""
    for line in lines:
        #check for content-length (determines how long to read for)
        if (line.startswith("Content-Length")):
            line = line.replace("Content-Length:", "")
            body_bytes = int(line)

        ## check for Last-Modified -- gives the date
        if (line.startswith("Last-Modified:")):
            line = line.replace("Last-Modified:", "")
            date = line

        ## checks the version -- must be http/1.0
        if (line.startswith("HTTP")):
            line = line.replace("HTTP/1.1", "HTTP/1.0")

    ## reads the length of the current body
    read_bytes = len(body)
    bytes_to_read = body_bytes - read_bytes
    
    ## runs unti no more bytes to read
    while(bytes_to_read > 0):
        additional_bytes = b""
        additional_bytes = socket.recv(bytes_to_read)

        body += additional_bytes
        bytes_to_read -= len(additional_bytes)

    return (header.decode("utf-8"), body, date)

### makes the request to be sent to the server
def make_request(dictionary):
    #Make request line
    request = ""
    request += str(dictionary.pop("Method:")) + " " + str(dictionary.pop("Path:")) + " " + str(dictionary.pop("Version:")) + "\r\n"
    
    # Put Host name
    request += "Host: " + str(dictionary.pop("Host:")) + "\r\n"

    #close the connection
    request += "Connection: close\r\n"

    # All other headers
    for header in dictionary:
        # ignore existing connection header
        if (header == "Connection:"):
            continue
        request += str(header) + " " + str(dictionary[header]) + "\r\n"
    
    request += "\r\n" # finish header with empty line

    return request

### Identifies which cache method to pass, if any
def cache_methods(dictionary): 
    # Gets the position where proxy is in the path (Want to still recognize commands even if they don't appear directly after host:port/)
    split_path = dictionary["Path:"].split("/")
    index = split_path.index("proxy")

    if (split_path[index + 2] in cacheMethods) :
        global cacheEnabled
        global cache

        match split_path[index + 2]:
            #enable the cache
            case "enable":
                cacheEnabled = True
            #disable the cache
            case "disable":
                cacheEnabled = False
            #empty the cache
            case "flush":
                cache.clear()
        return True
    else:
        # not a full cache method
        return False

## Checks if the path has a valid blocklist method
def blocklist_methods(dictionary):
    # Find position of proxy in path (want to still recognize blocklist even if doesn't come right after host:port)
    split_path = dictionary["Path:"].split("/")
    index = split_path.index("proxy")

    if (split_path[index + 2] in blocklistMethods):
        global blockListEnabled
        global blockList
        match split_path[index + 2]:
            #enable the block list
            case "enable":
                blockListEnabled = True
            # disable the blocklist
            case "disable":
                blockListEnabled = False
            # clear the block list
            case "flush":
                blockList.clear()
            # add to the block list
            case "add":
                # check if a domain name was actually specified - ignore otherwise
                if (len(split_path) != index + 3):
                    hostport = split_path[index + 3].split(":")
                    port = 80
                    # check for port
                    if (len(hostport) == 2):
                        #port specified
                        port = hostport[1]

                    blockList.update({hostport[0]: port})
            # remoce entry from block list
            case "remove":
                if (len(split_path) != index + 3):
                    blockList.pop(split_path[index + 3], "default")
        return True
    # not full command
    return False

### handles the client's request
def handle_request(clientSocket, addr) :
     #dictionary is a record of all necessary data relevant to the request (i.e headers methods, hostname, etc)
     dictionary = {}
     # read the request from the client
     request = read_request(clientSocket)
     # parse the request into separate components
     status = parse_request(request, dictionary)

     if (status != 200):
         # the request is not valid - send an error message
         error_message(clientSocket, status)
     else:
         ## DO NOT SEND IF CLIENT REQUEST WAS A COMMAND
         ## possible cache command
         if ("/proxy/cache/" in dictionary["Path:"]):
            lockCache.acquire()
            # check if cache command and execute it
            if ( cache_methods(dictionary) ):
                lockCache.release()
                # client request was a proxy cache command, close the socket and return early
                message = "HTTP/1.0 200 OK \r\n\r\n"
                clientSocket.send(message.encode("utf-8"))
                clientSocket.close()

                return
            lockCache.release()
            
        
        ## possible block list command
         if ("/proxy/blocklist/" in dictionary["Path:"]):
             lockBL.acquire()
             # check if block_list method and execute it
             if (blocklist_methods(dictionary)):
                 lockBL.release()
                 #client request was a valid blocklist command, close the socket and return early
                 message = "HTTP/1.0 200 OK \r\n\r\n"
                 clientSocket.send(message.encode("utf-8"))
                 clientSocket.close()
                 return
             lockBL.release()
        
         #request was not a command \/
         # check if host:port is blocked -- don't connect if it is
         if (blockListEnabled) :
             host = dictionary["Host:"]

             # check if any keys in the blocklist are contained in the host
             lockBL.acquire()
             for key in blockList:
                ## key is in the host -- deny connection
                if (key in host):
                    if (int(blockList[key]) == int(dictionary["Port:"])):
                        error_message(clientSocket, 403)
                        clientSocket.close()
                        lockBL.release()
                        return
             lockBL.release()

        ## connect to the server - not blocked and not a command
         server = socket(AF_INET, SOCK_STREAM)
         server.connect((dictionary.get("Host:"), int(dictionary.pop("Port:"))))
         if (cacheEnabled):
             ## Cache is enabled 
             lockCache.acquire()
             # cache keys are a combination of the hostname and path (not reliant on port)
             key = dictionary["Host:"] + dictionary["Path:"]
             lockCache.release()

             lockCache.acquire()
             if (key in cache):
                 # check if cache entry is actually up-to-date
                 cache_key = cache[key]
                 lockCache.release()

                # add a if-modified-since header
                 dictionary["If-Modified-Since:"] = cache_key[2]

                 # make the request and send it to the server
                 request = make_request(dictionary)
                 server.send(request.encode())

                 # read the response
                 (header, body) = read_response(server)
                 if ("304" in header.decode()):
                    # cache object is up-to-date
                    server.close()

                    clientSocket.send(cache_key[0])
                    clientSocket.send(cache_key[1])
                 else :
                    # cache object is NOT up-to-date, read new object and get date
                    (header, body, date) = parse_response(header, body, server)
                    header += "\r\n\r\n"

                    server.close()

                    # send new header and body
                    clientSocket.send(header.encode())
                    clientSocket.send(body)
                    lockCache.acquire()
                    # replace the object in the cache
                    cache[key] = (header, body, date)
                    lockCache.release()
             else:
                 lockCache.release()
                 ## add to cache - Not in cache
                 # Make and send the request to the server
                 server_request = make_request(dictionary)
                 server.send(server_request.encode("utf-8"))

                 # Read the response from the server and forward it to client
                 (header, body) = read_response(server)
                 (header, body, date) = parse_response(header, body, server)
                 header += "\r\n\r\n"
                 #modify the cache
                 if ("200" in header and date != ""):
                    #only put in cache if it was a successful request
                    lockCache.acquire()
                    cache[key] = (header.encode("utf-8"), body, date)
                    lockCache.release()

                 server.close()
                 ## send the client the response
                 clientSocket.send(header.encode("utf-8"))
                 clientSocket.send(body)
         else:
            #cache isn't enabled just do a regular request
            # Make and send the request to the server
            server_request = make_request(dictionary)
            server.send(server_request.encode())

            # Read the response from the server and forward it to client
            (header, body) = read_response(server)

            # reads a single response
            (header, body, date) = parse_response(header, body, server)
            header += "\r\n\r\n"

            #close server connection
            server.close()

            # forward response connection
            clientSocket.send(header.encode("utf-8"))
            clientSocket.send(body)

     clientSocket.close()

# Start of program execution
# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option('-p', type='int', dest='serverPort')
parser.add_option('-a', type='string', dest='serverAddress')
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = 'localhost'
if port is None:
    port = 2100

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# TODO: Set up sockets to receive requests
listen = socket(AF_INET, SOCK_STREAM)
listen.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

listen.bind((address, port))
listen.listen() # begin listening for incoming connections

# IMPORTANT!
# Immediately after you create your proxy's listening socket add
# the following code (where "skt" is the name of the socket here):
# skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Without this code the autograder may cause some tests to fail
# spuriously.
while True:
    #accept incoming connection
     clientSocket, addr = listen.accept()
     
     threading.Thread(target=handle_request, args=(clientSocket, addr)).start()