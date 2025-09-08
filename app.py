from flask import Flask, request, render_template_string
import socket
import requests

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Demo Recon Tool</title>
</head>
<body>
    <h2>All-in-One Recon Demo</h2>
    <form method="POST">
        <input type="text" name="target" placeholder="Enter domain or IP" required>
        <button type="submit">Scan</button>
    </form>
    {% if result %}
        <h3>Results for: {{ target }}</h3>
        <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    target = None
    if request.method == "POST":
        target = request.form.get("target")
        try:
            ip = socket.gethostbyname(target)
            try:
                r = requests.get(f"http://{target}", timeout=5)
                status = r.status_code
            except Exception as e:
                status = f"Could not fetch HTTP ({e})"
            result = f"Resolved IP: {ip}\nHTTP Status: {status}"
        except Exception as e:
            result = f"Error: {e}"
    return render_template_string(HTML_TEMPLATE, result=result, target=target)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

