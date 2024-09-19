#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import socket
import argparse
import urllib.error
import urllib.request
import threading
from queue import Queue

class Spose(object):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='Spose by Petruknisme',
            description='Squid Pivoting Open Port Scanner'
        )
        parser.add_argument("--proxy", help="Define proxy address url(http://xxx:3128)",
                            action="store", dest='proxy')
        parser.add_argument("--target", help="Define target IP behind proxy",
                            action="store", dest='target')
        parser.add_argument("--threads", help="Number of threads (default: 100)", type=int,
                            default=100, action="store", dest='threads')
        parser.add_argument("--timeout", help="Set request timeout (default: 10)", type=int,
                            default=10, action="store", dest='timeout')
        results = parser.parse_args()

        if results.target is None or results.proxy is None:
            parser.print_help()
            sys.exit()

        self.target = results.target
        self.proxy = results.proxy
        self.threads = results.threads
        self.timeout = results.timeout
        self.all_ports = list(range(1, 65536))  # Scanning all ports (list for accurate count)
        self.queue = Queue()
        self.scanned_ports = set()  # Use a set to track scanned ports accurately
        self.open_ports = []  # List to store open ports
        self.lock = threading.Lock()
        self.stop_event = threading.Event()  # Event to signal threads to stop
        self.last_progress = ''  # Store the last progress message to reprint it after port open messages

        print(f"Using proxy address {self.proxy}")

        # Set up the proxy handler
        proxy_handler = urllib.request.ProxyHandler({'http': self.proxy})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)

        # Fill the queue with all ports
        for port in self.all_ports:
            self.queue.put(port)

        # Start thread to listen for keyboard input (Enter key)
        listener_thread = threading.Thread(target=self.listen_for_input)
        listener_thread.daemon = True
        listener_thread.start()

        # Start threads for scanning
        try:
            self.run_threads()
        except KeyboardInterrupt:
            print("\nScan interrupted by user. Exiting...")
            self.stop_event.set()  # Signal all threads to stop
            sys.exit()

        # Verify that all ports have been scanned
        self.verify_scan_completion()

        # Display summary of open ports after scan is complete
        self.display_open_ports()

    def run_threads(self):
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.scan_port)
            t.daemon = True  # Set threads as daemon to ensure they exit when main thread exits
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def scan_port(self):
        sem = threading.Semaphore(self.threads)  # Limiter le nombre de threads actifs
        while not self.queue.empty() and not self.stop_event.is_set():
            port = self.queue.get()
            try:
                sem.acquire()
                url = f"http://{self.target}:{port}"
                request = urllib.request.Request(url)
                response = urllib.request.urlopen(request, timeout=self.timeout)
                data = response.read().decode('utf-8')
                
                # Filtrer les réponses spécifiques
                if "The requested URL could not be retrieved" in data:
                    return  # Ignore this port
                
                code = response.getcode()
                if code in {200, 301, 302, 401, 404}:
                    with self.lock:
                        print(f"{self.target} {port} seems OPEN (HTTP {code})")
                        sys.stdout.flush()  # Ensure it's printed immediately
                        self.open_ports.append(port)  # Track open ports
            except urllib.error.URLError:
                pass
            finally:
                sem.release()

            with self.lock:
                self.scanned_ports.add(port)  # Ensure ports are added only once

    def listen_for_input(self):
        total_ports = len(self.all_ports)  # Total number of ports
        while not self.stop_event.is_set():
            input()  # Wait for user to press Enter
            with self.lock:
                scanned = len(self.scanned_ports)  # Accurate count of scanned ports
                remaining_ports = self.queue.qsize()
                percentage = (scanned / total_ports) * 100  # Calculate percentage
                # Clear the last progress line
                sys.stdout.write('\r' + ' ' * len(self.last_progress) + '\r')
                # Update progress message
                self.last_progress = f"Progress: {scanned} ports scanned, {remaining_ports} remaining. {percentage:.2f}% completed."
                sys.stdout.write(self.last_progress)
                sys.stdout.flush()

    def verify_scan_completion(self):
        # Recheck the queue to see if there are ports that weren't scanned
        if not self.queue.empty():
            print("\nWarning: Some ports were not scanned, restarting the scan for the remaining ports.")
            # Re-scan the remaining ports in the queue
            while not self.queue.empty():
                port = self.queue.get()
                self.queue.put(port)
            self.run_threads()

    def display_open_ports(self):
        # Display summary of open ports
        print("\n\nScan complete. Summary of open ports:")
        if not self.open_ports:
            print("No open ports found.")
        else:
            for port in self.open_ports:
                print(f"Port {port} is open.")

if __name__ == '__main__':
    Spose = Spose()
