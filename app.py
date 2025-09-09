import subprocess
from flask import Flask, render_template, request
import nmap  # Make sure this library is used for parsing

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    subdomains = []
    ports = []  # This will now be a list of dictionaries for the template
    target = None
    nmap_error = None
    subfinder_error = None

    if request.method == "POST":
        target = request.form["target"]

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

        # Run nmap using the python-nmap library (FIXED VERSION)
        try:
            nm = nmap.PortScanner()
            # Using a faster, less intrusive scan that is more likely to work on a free host
            # -sS: SYN scan (requires root, may not work on Render) -> switched to -sT
            # -sT: TCP Connect scan (does not require root)
            # -F: Fast mode (scan top 100 ports)
            # -T4: Aggressive timing template
            # --host-timeout 2m: Give up on a host after 2 minutes
            scan_result = nm.scan(target, arguments='-sT -F -T4 --host-timeout 2m')
            ports = [] # Reset ports to an empty list for the new scan

            # Check if the scan found any hosts
            if 'scan' not in scan_result:
                nmap_error = "Nmap scan completed but found no hosts to scan."
            else:
                for host in nm.all_hosts():
                    # Check for TCP protocol results
                    if 'tcp' in nm[host]:
                        for port, port_info in nm[host]['tcp'].items():
                            # Create a dictionary for each port to pass to the template
                            ports.append({
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info['name'],
                                'version': port_info.get('version', 'N/A')  # Use .get to avoid KeyError
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
