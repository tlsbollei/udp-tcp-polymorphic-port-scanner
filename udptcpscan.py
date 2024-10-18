import socket
import threading
from abc import ABC, abstractmethod
from queue import Queue


class ConnectionError(Exception):
    pass


class PortScanner(ABC):
    def __init__(self, ip_address, port_range):
        self.ip_address = ip_address
        self.port_range = port_range
        self.open_ports = []

    @abstractmethod
    def scan_port(self, port):
        """Abstract method to be implemented by specific scanner types (TCP, UDP)."""
        pass

    def run_scan(self):
        """Start the scan over the specified port range."""
        print(f"Scanning {self.ip_address} over ports {self.port_range}")
        for port in range(self.port_range[0], self.port_range[1] + 1):
            self.scan_port(port)


class TCPScanner(PortScanner):
    def scan_port(self, port):
        try:
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  

           
            result = sock.connect_ex((self.ip_address, port))

            if result == 0:  
                print(f"TCP Port {port} is OPEN on {self.ip_address}")
                self.open_ports.append(port)
            sock.close()
        except socket.error as e:
            raise ConnectionError(f"Error connecting to {self.ip_address}:{port} - {e}")


class UDPScanner(PortScanner):
    def scan_port(self, port):
        try:
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)

            
            sock.sendto(b"", (self.ip_address, port))

            
            try:
                data, addr = sock.recvfrom(1024)
                print(f"UDP Port {port} is OPEN on {self.ip_address}")
                self.open_ports.append(port)
            except socket.timeout:
                pass  

            sock.close()
        except socket.error as e:
            raise ConnectionError(f"Error on UDP port {port} for {self.ip_address} - {e}")


class ThreadedPortScanner:
    def __init__(self, scanner_type, ip_list, port_range):
        self.scanner_type = scanner_type
        self.ip_list = ip_list
        self.port_range = port_range
        self.queue = Queue()

    def worker(self):
        """Worker thread to process the scanning job."""
        while not self.queue.empty():
            ip_address = self.queue.get()
            scanner = self.scanner_type(ip_address, self.port_range)
            scanner.run_scan()
            print(f"Open ports for {ip_address}: {scanner.open_ports}")
            self.queue.task_done()

    def start_scan(self, num_threads=5):
        """Start scanning multiple IP addresses concurrently."""
        
        for ip in self.ip_list:
            self.queue.put(ip)

       
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)

    
        self.queue.join()

        for thread in threads:
            thread.join()


if __name__ == "__main__":
    
    ip_list = ["IP ADRESS HERE", "IP ADRESS HERE", "IP ADRESS HERE"]
    port_range = (20, 100)  

    print("Starting TCP Scan...")
    
    tcp_threaded_scanner = ThreadedPortScanner(TCPScanner, ip_list, port_range)
    tcp_threaded_scanner.start_scan(num_threads=10)

    print("\nStarting UDP Scan...")
    
    udp_threaded_scanner = ThreadedPortScanner(UDPScanner, ip_list, port_range)
    udp_threaded_scanner.start_scan(num_threads=10)
