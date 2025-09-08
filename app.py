from flask import Flask, request, jsonify
import socket
import requests

app = Flask(__name__)

@app.route("/")
def home():
    return "Demo Recon Tool is Running 🚀"

@app.route("/recon", methods=["GET"])
def recon():
    target = request.args.get("target")
    if not target:
        return jsonify({"error": "Please provide a domain or IP using ?target="}), 400

    try:
        # Resolve IP
        ip = socket.gethostbyname(target)

        # HTTP status check
        try:
            r = requests.get(f"http://{target}", timeout=5)
            status = r.status_code
        except Exception as e:
            status = str(e)

        return jsonify({
            "domain": target,
            "resolved_ip": ip,
            "http_status": status
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
