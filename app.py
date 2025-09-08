from flask import Flask, request, render_template_string
import nmap  # pip install python-nmap

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>All-in-One Recon Demo</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #f2f2f2; }
        h1 { color: #333; }
        input, button { padding: 8px; margin: 5px 0; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; background: #fff; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #eee; }
    </style>
</head>
<body>
    <h1>All-in-One Recon Demo 🚀</h1>
    <form method="POST" action="/scan">
        <label>Enter Domain or IP:</label><br>
        <input type="text" name="target" required>
        <button type="submit">Scan</button>
    </form>

    {% if result %}
    <h2>Results for: {{ target }}</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
        </tr>
        {% for r in result %}
        <tr>
            <td>{{ r.port }}</td>
            <td>{{ r.state }}</td>
            <td>{{ r.service }}</td>
            <td>{{ r.version }}</td>
        </tr>
        {% endfor %}
    </table>
    {% endif %}

    {% if error %}
    <p style="color:red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    scanner = nmap.PortScanner()
    result_list = []
    error = None

    try:
        # Lightweight Nmap scan: top 100 ports, TCP connect, service/version detection
        scanner.scan(hosts=target, arguments='-sT -Pn -sV --top-ports 1000', timeout=150)

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    r = scanner[host][proto][port]
                    result_list.append({
                        "port": port,
                        "state": r["state"],
                        "service": r["name"],
                        "version": r.get("version", "")
                    })
    except Exception as e:
        error = f"Error during scan: {str(e)}"

    return render_template_string(HTML, result=result_list, target=target, error=error)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
