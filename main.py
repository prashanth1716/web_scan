'''
ip port scanning, 
ip -> domain,
domain -> ip
'''

import socket
import dp_scan
from concurrent.futures import ThreadPoolExecutor


#domain name to ip address
def scan():

    #varables
    get = ""
    ip_details = []
    port_list = {}
    port_num = 65536
    max_works = 400
    socket_timeout = 1

    #colours & styling front
    reset = "\033[0m"
    blod_text = "\033[1m"
    red = "\033[31m"
    green = "\033[32m"
    yellow = "\033[33m"
    blue = "\033[34m"
    pink = "\033[35m"
    cray = "\033[36m"
    white = "\033[37m"

    try:
        #get address or name by user
        print("\n"+"#"*30)
        print(pink+"Note: ⚠️ Unauthorized IP scanning, port scanning, TLS probing, or server name enumeration without explicit permission may be illegal and can result in security alerts, blocking, or legal action."
        "\nAnd 'q',crtl+C,crtl+D for quit"+reset)
        get = input(blod_text+cray+"Enter ip or domain name: "+yellow)
    
    except EOFError: 
        print(blod_text+blue+"\nThank you !!!!"+reset)      #if crtl + D for exit
        return
    
    except KeyboardInterrupt: 
        print(blod_text+blue+"\nThank you !!!!"+reset)     #if crtl + C for exit
        return
 
    get = "".join(get.split())     #remove spaces in text
    get = get.lower()     #text to lower

    if get == "q": print(blod_text+blue+"\nThank you !!!!"+reset)    #if 'q' for exit
    else:
        try:
            ip = socket.gethostbyname(get)
            ip_details = socket.gethostbyaddr(ip)
        except socket.gaierror as e:
            print()
            if e.errno == -5: print(blod_text+red+e.strerror+"\nDomain name much be .com .in or check internet......"+reset)
            elif e.errno == -2 : print(blod_text+red+e.strerror+"\nDon't enter 'http' or 'https' Enter valid name and check internet connection....."+reset)
            elif e.errno == -3 : print(blod_text+red+e.strerror+"\nCheck internet connection or DNS server down retry!!"+reset)
            return
        except socket.herror as e:
            if e.errno == 1: print(blod_text+red+"\nHost is up!!! but blocking your ping")
            return
        
        except KeyboardInterrupt: 
            print(blod_text+blue+"\nThank you !!!!"+reset)
            return
        except EOFError: 
            print(blod_text+blue+"\nThank you !!!!"+reset)
            return

        print(reset+"#"*30+"\n")

        #device name printing
        print(blod_text+pink+"Your Device host name: "+green+socket.gethostname())
        
        #name printing .....
        try:
            name = ip_details[0]
            print(pink+"Target Host name: "+green, end="")
            if len(name) == 0 : print("-")
            else:
                for i in name:
                    print(i,end="")
                print()

            #domain name printing .......
            domain_name = ip_details[1]
            print(pink+"Domain name: "+green, end="")
            if len(domain_name) == 0 : print("-")
            else:
                for i in domain_name:
                    print(i,end="")
                print()
            
            #ip address printing ......
            ip_address = ip_details[2]
            print(pink+"IP Addredd: "+green,end="")
            if len(ip_address) == 0: print("-")
            else:
                for i in ip_address:
                    print(i,end="")
                    ip_address = i
                    print()

        except IndexError:
            print(blod_text+red+"check internet connection ....."+reset)
            return 
        
        #port scan
        try: 
            get = input("\nDeep scan if you want any key or n for stop?: ")
        except KeyboardInterrupt: 
            print(blod_text+blue+"\nThank you !!!!"+reset)      #if crtl + C for exit
            return 
        except EOFError: 
            print(blod_text+blue+"\nThank you !!!!"+reset)      #if crtl + D for exit
            return 

        get = "".join(get.split())
        get = get.lower()
        
        if get == "n" or get == "no" or get == "q":  
            print(blod_text+blue+"\nThank you !!!!"+reset)
            return
        
        else:
            #port scan
            print(yellow)
            def scan_port(port):
                s =socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(socket_timeout)

                r = s.connect_ex((ip_address,port))

                print(f"\rscanning {port} /{port_num}       {round(abs(socket_timeout*((port-port_num) /max_works)))} about",end='')

                if r == 0:
                    try: port_list[socket.getservbyport(port)] = port
                    except: port_list[f"unkown_{port}"] = port

            #thread
            with ThreadPoolExecutor(max_workers=max_works) as e:    
                e.map(scan_port,range(1,port_num+1))
            
            #line clear
            print("\r"+" "*80+"\r",end='')

            #print port
            if len(port_list) != 0: print(pink+"port            serice")
            else: 
                print(red+"There are 0 ports or check your connection")
                return
            for service,port in port_list.items():
                print(green+str(port)+ " "*(16-len(str(port))) +service)

            print()
            #deep scan information
            try:
                print(pink+"Information"+green)
                if 80 in port_list.values(): 
                    dp = dp_scan.deep_scan(ip_address,80)
                    print("There are using '"+dp['server']+"' server in port 80.")
                if 443 in port_list.values():
                    dp = dp_scan.deep_scan(ip_address,443,host_name=name,ssl_scan=True)
                    if dp["server"] == "-":dp["server"] = "not found"
                    print("There are using '"+dp["server"]+"' server and using '"+dp["TLS"]+"' in 443.")
            except TypeError as e:
                print(red+e)
                return
                    
scan()