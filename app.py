from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

# Simple HTML template
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>All-in-One Recon Demo</title>
</head>
<body>
    <h1>All-in-One Recon Demo 🚀</h1>
    <form method="POST" action="/scan">
        <label>Enter Domain or IP:</label>
        <input type="text" name="target" required>
        <button type="submit">Scan</button>
    </form>

    {% if result %}
    <h2>Results for: {{ target }}</h2>
    <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    return render_template_string(HTML)

@app.route("/scan", methods=["GET", "POST"])
def scan():
    result = None
    target = None
    if request.method == "POST":
        target = request.form.get("target")
        try:
            # Aggressive scan with Nmap, skip ping
            result = subprocess.check_output(
                ["nmap", "-sT", "-A", "-Pn", target],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=180  # 3 minutes max
            )
        except subprocess.CalledProcessError as e:
            result = f"Error during scan:\n{e.output}"
        except subprocess.TimeoutExpired:
            result = "Error: Scan took too long and was stopped."
    return render_template_string(HTML, result=result, target=target)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
