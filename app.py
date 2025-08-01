from flask import Flask, render_template, request
import requests
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def scan():
    threat_info = None
    if request.method == 'POST':
        input_type = request.form['input_type']
        user_input = request.form['user_input']

        if input_type == "IP":
            api_key = os.environ.get("THREAT_API_KEY_1")
            if api_key:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={user_input}&maxAgeInDays=90"
                headers = {"Key": api_key, "Accept": "application/json"}
                response = requests.get(url, headers=headers)
                threat_info = response.json()
            else:
                threat_info = {"error": "Missing THREAT_API_KEY_1"}

        elif input_type == "URL":
            api_key = os.environ.get("THREAT_API_KEY_2")
            if api_key:
                url_scan = "https://www.virustotal.com/api/v3/urls"
                headers = {"x-apikey": api_key}
                data = {"url": user_input}

                scan_response = requests.post(url_scan, headers=headers, data=data)
                scan_data = scan_response.json()

                url_id = scan_data.get("data", {}).get("id")
                if url_id:
                    url_report = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
                    report_response = requests.get(url_report, headers=headers)
                    threat_info = report_response.json()
                else:
                    threat_info = {"error": "Could not retrieve scan ID from VirusTotal"}
            else:
                threat_info = {"error": "Missing THREAT_API_KEY_2"}

    return render_template("index.html", threat_info=threat_info)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
