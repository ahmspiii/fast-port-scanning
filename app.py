from flask import Flask, render_template, request, jsonify
import socket
import threading
import concurrent.futures
from queue import Queue
import time
from datetime import datetime

app = Flask(__name__)

# Common ports and their services
COMMON_PORTS = {
    # Common services
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    115: 'SFTP',
    135: 'MS RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    194: 'IRC',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    514: 'Syslog',
    587: 'SMTP',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1080: 'SOCKS',
    1433: 'MSSQL',
    1521: 'Oracle',
    2049: 'NFS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5632: 'PCAnywhere',
    5900: 'VNC',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    8888: 'HTTP-Alt',
    9000: 'PHP-FPM',
    9090: 'Webmin',
    27017: 'MongoDB',
    27018: 'MongoDB',
    27019: 'MongoDB'
}

def port_scan(target, port, timeout=2):
    """Scan a single port on the target IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                print(f"[+] Port {port} ({service}) is open on {target}")
                return port, service
            else:
                print(f"[-] Port {port} is closed on {target}")
    except socket.timeout:
        print(f"[!] Timeout while scanning port {port} on {target}")
    except socket.error as e:
        print(f"[!] Socket error on port {port}: {e}")
    except Exception as e:
        print(f"[!] Unexpected error scanning port {port}: {e}")
    return None

def scan_ports(target, port_list, max_workers=100):
    """Scan multiple ports using thread pool."""
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(port_scan, target, port): port 
            for port in port_list
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                port, service = result
                open_ports.append({
                    'port': port,
                    'service': service,
                    'status': 'open'
                })
    
    return sorted(open_ports, key=lambda x: x['port'])

@app.route('/')
def home():
    """Render the main page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle port scan requests."""
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'error': 'No IP address provided'}), 400
            
        target = data.get('ip', '').strip()
        print(f"\n[+] Starting port scan for {target}")
        
        # Validate IP address
        if not target:
            return jsonify({'error': 'No IP address provided'}), 400
            
        try:
            # Basic IP validation
            socket.inet_aton(target)
        except socket.error:
            return jsonify({'error': 'Invalid IP address format'}), 400
        
        # Get ports to scan (common ports by default)
        port_list = list(COMMON_PORTS.keys())
        print(f"[i] Will scan {len(port_list)} common ports")
        
        try:
            # Test if host is reachable with a quick ping
            print(f"[i] Testing if host is reachable...")
            socket.gethostbyname(target)
            print("[+] Host is reachable, starting scan...")
            
            # Start the scan with a timeout of 60 seconds
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(scan_ports, target, port_list)
                try:
                    open_ports = future.result(timeout=60)  # 60 seconds timeout
                except concurrent.futures.TimeoutError:
                    return jsonify({
                        'error': 'Scan timed out after 60 seconds. The target might be blocking our requests.'
                    }), 408
                    
            # Calculate scan duration
            duration = round(time.time() - start_time, 2)
            
            print(f"[+] Scan completed in {duration} seconds")
            print(f"[+] Found {len(open_ports)} open ports")
            
            return jsonify({
                'ip': target,
                'open_ports': [p['port'] for p in open_ports],
                'scan_info': {
                    'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': f"{duration} seconds",
                    'ports_scanned': len(port_list),
                    'open_ports_count': len(open_ports)
                }
            })
            
        except socket.gaierror:
            return jsonify({
                'error': 'Could not resolve hostname. Please check the IP/domain and try again.'
            }), 400
            
    except Exception as e:
        error_msg = f'An error occurred during the scan: {str(e)}'
        print(f"[!] {error_msg}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': error_msg}), 500

if __name__ == '__main__':
    # Run without debug mode to avoid threading issues
    app.run(host='0.0.0.0', port=5000, debug=False)
