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

    # 3. Check for obviously malicious patterns FIRST
    malicious_patterns = [
        r"^127\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\.",
        r"^0\.",
        r"^169\.254\.",
        r"^localhost",
        r"^::1",
        r"\.\./",    # Path traversal
        r"[<>'\"]",  # XSS/SQLi attempts
    ]
    
    for pattern in malicious_patterns:
        if re.search(pattern, cleaned_target):
            return False, "🕵️ Good luck, We log every keystroke… including this lame attempt."

    # 4. Check if it's a valid IPv4 address
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    ipv4_match = re.match(ipv4_pattern, cleaned_target)
    if ipv4_match:
        try:
            for octet in ipv4_match.groups():
                if not 0 <= int(octet) <= 255:
                    return False, "Invalid IP address"
            return True, cleaned_target
        except ValueError:
            return False, "Invalid IP address"

    # 5. Check if it's a valid domain name
    # Simple check: must contain a dot and only allowed characters
    if "." in cleaned_target:
        # Basic character validation
        if re.match(r'^[a-z0-9.-]+$', cleaned_target):
            # Check it doesn't start/end with hyphen or dot
            if not (cleaned_target.startswith('-') or cleaned_target.startswith('.') or 
                    cleaned_target.endswith('-') or cleaned_target.endswith('.')):
                return True, cleaned_target

    # 6. If we get here, it's invalid input
    return False, "🕵️ Good luck, We log every keystroke… including this lame attempt."
    
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
            flash(validation_result)  # Show warning message
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
