import socket,ssl

def deep_scan(target,port,host_name='',ssl_scan=False):
    result = {}
    #ssl or tsl
    try:
        
        if port == 443:
            con = ssl._create_unverified_context()
            with socket.create_connection((target,port),timeout=3) as sock:
                with con.wrap_socket(sock,server_hostname=host_name) as ssock:
                    ssock.send(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
                    data_server = ssock.recv(4096).decode(errors="ignore")   #recv data
                    data_ssl = ssock.version()  #TLS = transport layer security or SSL = secure sockets layer
                    

        elif port == 80:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect((target,port))
            s.send("HEAD / HTTP/1.0\r\n\r\n".encode())
            data_server = s.recv(4096).decode()

    except Exception as e: #error
        return e
    
    for line in data_server.split("\r\n"):
        if "Server" in line:
            data_server = line.replace("Server: ",'')
            break
        
    if "\r\n" in data_server:
        data_server = ""
    
    if ssl_scan:
        #tls
        try:
            if len(data_ssl) == 0: result["TLS"] = "-"
            else: result["TLS"] = data_ssl
        except UnboundLocalError:
            return "SSL&TLS use only on 443 port"
        #server
        if len(data_server) == 0: result["server"] = "-"
        else: result["server"] = data_server
        #return value 
        return result
    else:
        #server
        if len(data_server) == 0: result["server"] = "-"
        else: result["server"] = data_server
        #return value 
        return result
    
   