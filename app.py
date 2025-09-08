import subprocess
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    subdomains = []
    ports = []
    target = None

    if request.method == "POST":
        target = request.form["target"]

        # Run subfinder
        try:
            result = subprocess.run(
                ["subfinder", "-d", target, "-silent"],
                capture_output=True, text=True, check=True
            )
            subdomains = result.stdout.splitlines()
        except Exception as e:
            subdomains = [f"Error running subfinder: {e}"]

        # Run nmap (TCP connect scan, service detection, version)
        try:
            result = subprocess.run(
                ["nmap", "-sT", "-sV", "-Pn", target],
                capture_output=True, text=True, check=True
            )
            ports = result.stdout.splitlines()
        except Exception as e:
            ports = [f"Error running nmap: {e}"]

    return render_template(
        "index.html",
        subdomains=subdomains,
        ports=ports,
        target=target
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
