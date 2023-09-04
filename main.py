from scapy.all import ARP, Ether, srp
from argparse import ArgumentParser
from queue import Queue
from threading import Thread, Lock
import socket

N_THREADS = 500
queue1 = Queue()



def open_port(port):
    try: 
            s = socket.socket()
            s.connect((host, port))
    except:
            with Lock():
                return False
    else:
            with Lock():
                print(f"{host:15}:{port:5} is open ")
    finally:
        s.close()
        
def scan():
    global queue1
    while True:
        worker = queue1.get()
        open_port(worker)
        queue1.task_done()

def main (host, ports):
    global queue1 
    for thread1 in range(N_THREADS):
        thread1 = Thread(target=scan)
        thread1.daemon = True
        thread1.start()
    for worker in ports:
        queue1.put(worker)
    queue1.join()
    
parser = ArgumentParser()
parser.add_argument('-t', "--target", help="Use -t to add your target.", required=True)
args = parser.parse_args()
target_ip = args.target
arp = ARP(pdst=target_ip)
ether = Ether(dst='ff:ff:ff:ff:ff:ff')
packet = ether/arp
result = srp(packet, timeout=3, verbose=0) [0]
clients = []
for sent, recieved in result:
    clients.append({'ip': recieved.psrc, 'mac' : recieved.hwsrc})
print("Devices in the network:")
print("IP" + " "*18+"MAC")
for client in clients:
    print("{:16}  {}".format(client['ip'], client['mac']))
print("What would you like to do next?")
print("1. Port Scan")
print("2. Quit")
answer = input("Enter number\n")

if answer =="1":
    host = input("Enter the host ip address:")
    print ("what ports would you like to scan?")
    ports = input("enter the range of ports (1-etc):")
    host, port_range = host, ports
    
    start_port, end_port = port_range.split("-")
    start_port, end_port = int(start_port),int(end_port)
    
    ports = [p for p in range(start_port, end_port)]
    
    main(host, ports)
    
    print("Scan completed :)")
    
else:
    exit()
    
