from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

# Simple HTML template
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Demo Recon Tool</title>
</head>
<body>
    <h1>Demo Recon Tool 🚀</h1>
    <form method="POST" action="/scan">
        <label>Enter Domain or IP:</label>
        <input type="text" name="target" required>
        <button type="submit">Run Aggressive Nmap Scan</button>
    </form>

    {% if result %}
    <h2>Scan Result:</h2>
    <pre>{{ result }}</pre>
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
    try:
        # Run aggressive Nmap scan (-A)
        result = subprocess.check_output(["nmap", "-A", target], text=True, stderr=subprocess.STDOUT, timeout=120)
    except subprocess.CalledProcessError as e:
        result = f"Error: {e.output}"
    except subprocess.TimeoutExpired:
        result = "Error: Scan took too long and was stopped."

    return render_template_string(HTML, result=result)

if __name__ == "__main__":
    app.run(port=8080)
