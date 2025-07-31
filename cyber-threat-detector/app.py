from flask import Flask, render_template, request
import requests

app = Flask(__name__)

API_KEY = 'your_virustotal_or_abuseipdb_api_key'

@app.route("/", methods=["GET", "POST"])
def index():
    threat_info = None
    if request.method == "POST":
        input_type = request.form["input_type"]
        user_input = request.form["user_input"]

        if input_type == "IP":
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={user_input}",
                headers={"Key": API_KEY, "Accept": "application/json"}
            )
            data = response.json()
            threat_info = data.get("data", {})

        elif input_type == "URL":
            headers = {"x-apikey": API_KEY}
            response = requests.get(f"https://www.virustotal.com/api/v3/urls", headers=headers)
            threat_info = {"message": "URL scanning requires POST encoding. To be implemented."}

    return render_template("index.html", threat_info=threat_info)

if __name__ == "__main__":
    app.run(debug=True)
