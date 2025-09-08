from flask import Flask, request, render_template_string
import subprocess
import socket
import concurrent.futures

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>All-in-One Recon Demo 🚀</title>
</head>
<body>
    <h1>All-in-One Recon Demo 🚀</h1>
    <form method="POST">
        <label>Enter Domain or IP:</label>
        <input type="text" name="target" required>
        <button type="submit"> Scan </button>
    </form>

    {% if target %}
        <h2>Results for: {{ target }}</h2>
        
        <h3>Subdomains</h3>
        <pre>{{ subdomains }}</pre>
        
        <h3>Port Scan (Nmap)</h3>
        <table border="1" cellpadding="5">
            <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
            {% for row in nmap_results %}
            <tr>
                <td>{{ row['port'] }}</td>
                <td>{{ row['state'] }}</td>
                <td>{{ row['service'] }}</td>
                <td>{{ row['version'] }}</td>
            </tr>
            {% endfor %}
        </table>
    {% endif %}
</body>
</html>
"""

def run_subfinder(target):
    try:
        cmd = ["subfinder", "-silent", "-d", target]
        result = subprocess.check_output(cmd, text=True, timeout=60)
        return result.strip() if result else "No subdomains found."
    except Exception as e:
        return f"Error running subfinder: {str(e)}"

def run_nmap(target):
    try:
        cmd = ["nmap", "-sT", "-Pn", "-T4", "-sV", target]
        result = subprocess.check_output(cmd, text=True, timeout=60)
        
        # Parse into structured table
        rows = []
        for line in result.splitlines():
            if "/tcp" in line:
                parts = line.split()
                port = parts[0]
                state = parts[1]
                service = parts[2] if len(parts) > 2 else ""
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                rows.append({"port": port, "state": state, "service": service, "version": version})
        return rows
    except Exception as e:
        return [{"port": "Error", "state": str(e), "service": "", "version": ""}]

@app.route("/", methods=["GET", "POST"])
def index():
    target = None
    subdomains = None
    nmap_results = []

    if request.method == "POST":
        target = request.form["target"]

        with concurrent.futures.ThreadPoolExecutor() as executor:
            subdomain_future = executor.submit(run_subfinder, target)
            nmap_future = executor.submit(run_nmap, target)

            subdomains = subdomain_future.result()
            nmap_results = nmap_future.result()

    return render_template_string(HTML_TEMPLATE, target=target, subdomains=subdomains, nmap_results=nmap_results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
