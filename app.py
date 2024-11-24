from flask import Flask, render_template, request
import subprocess
import requests
import phonenumbers
import base64

app = Flask(__name__)

API_KEY = "SECRET_KEY"

# Route for Home Page
@app.route('/')
def index():
    return render_template('index.html')

# Route for Nmap Scan
@app.route('/scan_nmap', methods=['POST'])
def scan_nmap():
    url = request.form['url']
    try:
        nmap_result = subprocess.run(['nmap', '-vvv', url], capture_output=True, text=True)
        result = nmap_result.stdout
    except Exception as e:
        result = str(e)
    return render_template('result.html', tool='Nmap', results=result, url=url)

# Route for WHOIS Scan
@app.route('/scan_whois', methods=['POST'])
def scan_whois():
    url = request.form['url']
    try:
        whois_result = subprocess.run(['whois', url], capture_output=True, text=True)
        result = whois_result.stdout
    except Exception as e:
        result = str(e)
    return render_template('result.html', tool='WHOIS', results=result, url=url)

# Route for Nikto Scan
@app.route('/scan_nikto', methods=['POST'])
def scan_nikto():
    url = request.form['url']
    try:
        nikto_result = subprocess.run(['perl', 'nikto.pl', '-h', url], capture_output=True, text=True)
        result = nikto_result.stdout
    except Exception as e:
        result = str(e)
    return render_template('result.html', tool='Nikto', results=result, url=url)

@app.route('/scan_clickjacking', methods=['POST'])
def scan_clickjacking():
    url = request.form['url']
    try:
        clickjack_result = subprocess.run(['curl', '-I', url], capture_output=True, text=True)
        headers = clickjack_result.stdout
        if 'X-Frame-Options' in headers:
            result = "Clickjacking protection is enabled."
        else:
            result = "Clickjacking protection is NOT enabled."
    except Exception as e:
        result = str(e)
    return render_template('result.html', tool='Clickjacking', results=result, url=url)

# Route for OWASP ZAP Scan
@app.route('/scan_zap', methods=['POST'])
def scan_zap():
    url = request.form['url']
    try:
        zap_result = subprocess.run(['zap-cli', 'quick-scan', url], capture_output=True, text=True)
        result = zap_result.stdout
    except Exception as e:
        result = str(e)
    return render_template('result.html', tool='OWASP ZAP', results=result, url=url)

# Route for URL Content Scanner
@app.route('/scan_url', methods=['POST'])
def scan_url():
    url = request.form['url']
    try:
        curl_result = subprocess.run(['curl', url], capture_output=True, text=True)
        result = curl_result.stdout
    except Exception as e:
        result = str(e)
    return render_template('result.html', tool='URL Scanner', results=result, url=url)

# Route for Subdomain Enumeration
@app.route('/scan_subdomains', methods=['POST'])
def scan_subdomains():
    url = request.form['url']
    try:
        subdomain_result = subprocess.run(['sublist3r', '-d', url], capture_output=True, text=True)
        result = subdomain_result.stdout
    except Exception as e:
        result = str(e)
    return render_template('result.html', tool='Subdomain Enumeration', results=result, url=url)

# Route for XSS Scan
@app.route('/scan_xss', methods=['POST'])
def scan_xss():
    url = request.form['url']
    try:
        xss_result = subprocess.run(
            ['python3', 'xsstrike.py', '-u', url],
            capture_output=True,
            text=True,
            check=True
        )
        result = xss_result.stdout.strip() or xss_result.stderr.strip()
    except subprocess.CalledProcessError as e:
        result = f"Error: {e.stderr.strip()}" if e.stderr.strip() else str(e)
    except Exception as e:
        result = str(e)

    return render_template('result.html', tool='XSS Scan', results=result, url=url)

# Route for VirusTotal Scan
@app.route('/scan_virustotal', methods=['POST'])
def scan_virustotal():
    url = request.form['url']
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode()

    try:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{encoded_url}',
            headers={'x-apikey': API_KEY}
        )
        
        if response.status_code == 200:
            analysis_result = response.json()

            last_analysis = analysis_result['data']['attributes']['last_analysis_results']
            issues = []
            security_parameters = []

            for engine, details in last_analysis.items():
                result = details['result']
                category = details['category']
                security_parameters.append(f"{engine.capitalize()}: {result} ({category})")

                if category == 'malicious':
                    issues.append(f"{engine.capitalize()}: {result}")

            if issues:
                result_message = "Security Issues Detected:"
                issues_list = "<br>".join(issues)
            else:
                result_message = "The URL is safe."
                issues_list = ""

            security_info = "<br>".join(security_parameters)

        else:
            result_message = f"Error {response.status_code}: {response.text}"
            issues_list = ""
            security_info = ""

    except Exception as e:
        result_message = str(e)
        issues_list = ""
        security_info = ""

    return render_template('result.html', tool='VirusTotal', results=result_message, issues=issues_list, security_info=security_info, url=url)

# Phone Number Validator
@app.route('/validate_phone', methods=['POST'])
def validate_phone():
    phone_number = request.form['phone']
    try:
        parsed_number = phonenumbers.parse(phone_number, None)
        if phonenumbers.is_valid_number(parsed_number):
            result = f"{phone_number} is a valid phone number."
        else:
            result = f"{phone_number} is NOT a valid phone number."
    except Exception as e:
        result = str(e)

    return render_template('result.html', tool='Phone Validator', results=result, phone=phone_number)

# Generate User Details
@app.route('/generate', methods=['GET', 'POST'])
def generate_details():
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        location = request.form.get('location', '')
        details = {
            "name": name,
            "email": email,
            "location": location,
            "user_info": generate_user_info(name, email, location)
        }
        return render_template('results.html', details=details)
    return render_template('generate.html')

def generate_user_info(name, email, location):
    return f"{name} is located in {location}. You can contact them at {email}."

if __name__ == '__main__':
    app.run("0.0.0.0", port=4000)
