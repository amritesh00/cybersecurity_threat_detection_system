from flask import Flask, render_template, request
import requests
import os

app = Flask(__name__)

# Replace with your actual API keys
API_KEY_1 = os.environ.get("THREAT_API_KEY_1", "756b79aa76926048db6d76f32dc4ad5cea72943bb859ff7777aac0366e2911fec3703563f38bc65f")
API_KEY_2 = os.environ.get("THREAT_API_KEY_2", "9d0a36f577cfd26388958fdc5a504c6398c63ada431237fcbf058c4ee4ab1721")

# Home page
@app.route('/')
def home():
    return render_template('index.html')

# Threat detection route
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']

    # API 1 call (e.g., VirusTotal)
    headers1 = {
        "x-apikey": API_KEY_1
    }
    response1 = requests.get(f"https://www.virustotal.com/api/v3/urls", headers=headers1)
    result1 = response1.json()

    # API 2 call (you can replace this with another threat intel API)
    headers2 = {
        "Authorization": f"Bearer {API_KEY_2}"
    }
    response2 = requests.get(f"https://api.threatintelligenceplatform.com/v1/url?url={url}&apikey={API_KEY_2}")
    result2 = response2.json()

    return render_template("result.html", url=url, result1=result1, result2=result2)

# Run the app
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
