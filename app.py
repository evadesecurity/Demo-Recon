import re
import subprocess
from flask import Flask, render_template, request, flash
import nmap

app = Flask(__name__)
app.secret_key = 'evade-security-demo-key-2024'  # Required for flash

def is_valid_target(input_target):
    """
    Validates if the input is a valid domain name or IP address.
    Returns (True, cleaned_target) if valid, (False, error_message) if invalid.
    """
    # 1. Clean the input
    cleaned_target = input_target.strip().lower()
    
    # Remove http://, https://, and trailing slash
    cleaned_target = re.sub(r'^https?://', '', cleaned_target)
    cleaned_target = re.sub(r'/$', '', cleaned_target)
    
    # 2. Check for empty input
    if not cleaned_target:
        return False, "Please enter a domain or IP address."

    # 3. Check if it's a valid IPv4 address (e.g., 8.8.8.8)
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    ipv4_match = re.match(ipv4_pattern, cleaned_target)
    if ipv4_match:
        # Validate each octet is between 0-255
        try:
            for octet in ipv4_match.groups():
                if not 0 <= int(octet) <= 255:
                    return False, "Invalid IP address. Octets must be between 0-255."
            # Check if it's a PRIVATE IP (show warning)
            octets = list(map(int, ipv4_match.groups()))
            # Check for private IP ranges
            if (octets[0] == 10 or
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168) or
                (octets[0] == 127 and octets[1] == 0 and octets[2] == 0 and octets[3] == 1)):
                return False, "🕵️ We log every keystroke… including this lame attempt."
            return True, cleaned_target  # Valid PUBLIC IP
        except ValueError:
            pass  # This will be caught by the final return False

    # 4. Check if it's a valid domain name (e.g., google.com)
    # A simple but effective check: must contain a dot and only allowed characters
    domain_pattern = r'^[a-z0-9.-]+\.[a-z]{2,}$'
    if re.match(domain_pattern, cleaned_target):
        return True, cleaned_target  # Valid domain

    # 5. If it's NOT a valid IP AND NOT a valid domain → Show Hacker Warning
    return False, "🕵️ We log every keystroke… including this lame attempt."

@app.route("/", methods=["GET", "POST"])
def index():
    subdomains = []
    ports = []
    target = None
    nmap_error = None
    subfinder_error = None

    if request.method == "POST":
        raw_target = request.form["target"]

        # Validate the input
        is_valid, validation_result = is_valid_target(raw_target)
        
        if not is_valid:
            flash(validation_result)  # Show error message
            return render_template("index.html", target=raw_target)
        
        # Use the cleaned target
        target = validation_result

        # Run subfinder
        try:
            result = subprocess.run(
                ["subfinder", "-d", target, "-silent"],
                capture_output=True, text=True, check=True, timeout=120
            )
            subdomains = result.stdout.splitlines()
        except subprocess.TimeoutExpired:
            subfinder_error = "Subfinder scan timed out (took longer than 2 minutes)."
        except subprocess.CalledProcessError as e:
            subfinder_error = f"Subfinder failed to run. Error: {e.stderr}"
        except Exception as e:
            subfinder_error = f"Unexpected error running subfinder: {e}"

        # Run nmap
        try:
            nm = nmap.PortScanner()
            scan_result = nm.scan(target, arguments='-sT -F -T4 -Pn --host-timeout 2m')
            ports = []
            if 'scan' in scan_result:
                for host in nm.all_hosts():
                    if 'tcp' in nm[host]:
                        for port, port_info in nm[host]['tcp'].items():
                            ports.append({
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info['name'],
                                'version': port_info.get('version', 'N/A')
                            })
        except nmap.PortScannerError as e:
            nmap_error = f"Nmap PortScanner error: {str(e)}"
        except Exception as e:
            nmap_error = f"Unexpected error running nmap: {e}"

    return render_template(
        "index.html",
        subdomains=subdomains,
        ports=ports,
        target=target,
        nmap_error=nmap_error,
        subfinder_error=subfinder_error
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
