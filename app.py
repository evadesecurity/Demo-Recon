import re
import subprocess
from flask import Flask, render_template, request, flash
import nmap

app = Flask(__name__)
# The secret_key line is NOT needed. Removed.

def is_valid_target(input_target):
    """
    Validates if the input is a likely valid domain name, IPv4, or IPv6 address.
    This is a basic validation to catch obvious mistakes and malicious input.
    """
    # Clean the input: remove http/https and trailing slashes
    original_input = input_target
    input_target = input_target.strip().lower()
    # Remove http://, https://, and trailing slash
    input_target = re.sub(r'^https?://', '', input_target)
    input_target = re.sub(r'/$', '', input_target)

    # Basic check for empty or very long input
    if not input_target or len(input_target) > 253:
        return False, "Input is too long or empty."

    # Common SSRF and internal IP patterns to BLOCK
    malicious_patterns = [
        r"^localhost$",
        r"^127\.\d+\.\d+\.\d+$",
        r"^10\.\d+\.\d+\.\d+$",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$",
        r"^192\.168\.\d+\.\d+$",
        r"^0\.\d+\.\d+\.\d+$",
        r"^169\.254\.\d+\.\d+$",
        r"^::1$",
        r"^fc00::",
        r"^fd00::",
        r"\.\.",  # Basic path traversal attempt
        r"[<>'\"]",  # Basic XSS/SQLi attempt
    ]

    for pattern in malicious_patterns:
        if re.match(pattern, input_target):
            # Check if the original input was just a URL with http/https
            if re.match(r'^https?://', original_input) and not re.match(pattern, original_input):
                # It was just a URL, return the cleaned version
                return True, input_target
            else:
                # It's a real malicious attempt
                return False, "🕵️ good luck, We log every keystroke… including this lame attempt."

    # Regex for valid domain names (e.g., example.com, sub.example.com)
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    # Regex for valid IPv4 address
    ipv4_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Regex for valid IPv6 address (simplified)
    ipv6_regex = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'

    # Check if input matches any valid pattern
    if (re.match(domain_regex, input_target, re.IGNORECASE) or
        re.match(ipv4_regex, input_target) or
        re.match(ipv6_regex, input_target)):
        # Additional check for valid IPv4 octets
        if re.match(ipv4_regex, input_target):
            octets = input_target.split('.')
            for octet in octets:
                if not (0 <= int(octet) <= 255):
                    return False, "Invalid IPv4 address."
        return True, input_target

    return False, "Invalid input. Please enter a valid domain name or IP address."

@app.route("/", methods=["GET", "POST"])
def index():
    subdomains = []
    ports = []
    target = None
    nmap_error = None
    subfinder_error = None

    if request.method == "POST":
        raw_target = request.form["target"]  # Get the raw input for cleaning

        # --- CRITICAL SECURITY VALIDATION ---
        is_valid, validation_result = is_valid_target(raw_target)
        
        if not is_valid:
            flash(validation_result) # This will be the error message
            return render_template("index.html", target=raw_target) # Pass raw input back to show in form
        
        # If valid, the validation_result is the cleaned target (e.g., "domain.com")
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

        # Run nmap using the python-nmap library
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
