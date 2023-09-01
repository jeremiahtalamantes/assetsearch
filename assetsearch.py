##
##
## Asset Search with nmap
##
## Usage: python assetsearch.py 192.168.1.1/24 -o results.txt
##
##
## (Required: pip install python-nmap)
##

import nmap
import argparse

class NetworkScanner:
    def __init__(self, ip_range):
        self.ip_range = ip_range
        self.nm = nmap.PortScanner()
        self.results = []

    def scan(self):
        self.nm.scan(hosts=self.ip_range, arguments='-sn -O')

    def display_results(self, output_file=None):
        for host in self.nm.all_hosts():
            result_str = f"Host: {host} ({self.nm[host].hostname()})"
            self.results.append(result_str)
            print(result_str)
            
            if 'osclass' in self.nm[host]:
                for osclass in self.nm[host]['osclass']:
                    os_info = f"OS: {osclass['osfamily']} ({osclass['osgen']})"
                    device_type = f"Device Type: {osclass['osclass_type']}"
                    self.results.extend([os_info, device_type])
                    print(os_info)
                    print(device_type)
            
            self.results.append("----")
            print("----")

        if output_file:
            with open(output_file, 'w') as f:
                f.write('\n'.join(self.results))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("ip_range", help="The IP range to scan. E.g., 192.168.1.1/24")
    parser.add_argument("-o", "--output", help="Output file to store the results", default=None)

    args = parser.parse_args()

    scanner = NetworkScanner(args.ip_range)
    scanner.scan()
    scanner.display_results(args.output)