from flask import Flask, render_template, request
import requests
import base64

app = Flask(__name__)

# Replace with your actual API keys
ABUSE_IP_KEY = "756b79aa76926048db6d76f32dc4ad5cea72943bb859ff7777aac0366e2911fec3703563f38bc65f"
VIRUSTOTAL_KEY = "9d0a36f577cfd26388958fdc5a504c6398c63ada431237fcbf058c4ee4ab1721"

@app.route("/", methods=["GET", "POST"])
def index():
    threat_info = None
    error = None

    if request.method == "POST":
        input_type = request.form["input_type"]
        user_input = request.form["user_input"].strip()

        try:
            if input_type == "IP":
                response = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check?ipAddress={user_input}",
                    headers={"Key": ABUSE_IP_KEY, "Accept": "application/json"}
                )
                if response.status_code == 200:
                    threat_info = response.json().get("data", {})
                else:
                    error = f"AbuseIPDB Error: {response.status_code} - {response.text}"

            elif input_type == "URL":
                # Encode URL in base64 (VirusTotal format)
                url_id = base64.urlsafe_b64encode(user_input.encode()).decode().strip("=")
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": VIRUSTOTAL_KEY}
                )
                if response.status_code == 200:
                    data = response.json()
                    threat_info = data.get("data", {}).get("attributes", {})
                else:
                    error = f"VirusTotal Error: {response.status_code} - {response.text}"

        except Exception as e:
            error = f"Exception occurred: {str(e)}"

    return render_template("index.html", threat_info=threat_info, error=error)

if __name__ == "__main__":
    app.run(debug=True)
