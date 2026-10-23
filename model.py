import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
from flask import Flask, request, render_template,jsonify
import joblib
import json


app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('index.html')

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def get_abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def get_fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def get_tld_length(url):
    tld = get_tld(url, fail_silently=True)
    try:
        return len(tld)
    except:
        return -1

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def get_inputs(url):
    use_of_ip = having_ip_address(url)
    abnormal_url = get_abnormal_url(url)
    count_fullstop = url.count('.')
    count_www = url.count('www')
    count_at = url.count('@')
    count_dir = urlparse(url).path.count('/')
    count_embed_domain = urlparse(url).path.count('//')
    short_url = shortening_service(url)
    count_https = url.count('https')
    count_http = url.count('http')
    count_percentage = url.count('%')
    count_questionmark = url.count('?')
    count_hipen = url.count('-')
    count_equal = url.count('=')
    url_length = len(str(url))
    hostname_length  = len(urlparse(url).netloc)
    sus_url = suspicious_words(url)
    fd_length = get_fd_length(url)
    tld_length = get_tld_length(url)
    count_digits = digit_count(url)
    count_letters = letter_count(url)
    return pd.DataFrame(np.array([[use_of_ip, abnormal_url, count_fullstop, count_www, count_at, count_dir, count_embed_domain, short_url, count_https, count_http, count_percentage, count_questionmark, count_hipen, count_equal, url_length, hostname_length, sus_url, fd_length, tld_length, count_digits, count_letters]]), columns=['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@','count_dir', 'count_embed_domian', 'short_url', 'count-https','count-http', 'count%', 'count?', 'count-', 'count=', 'url_length','hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits','count-letters'])
    
def predict_model(url):
    inputs = get_inputs(url)
    joblib_LR_model = joblib.load('model.pkl')
    Ypredict = joblib_LR_model.predict(inputs)  
    return Ypredict[0]



def is_valid_url(url):
    """Check HTTP(S) syntax only; never fetch or assess the URL's safety."""
    if not url or any(char.isspace() or ord(char) < 32 or ord(char) == 127
                      for char in url) or '\\' in url:
        return False
    try:
        parsed = urlparse(url)
        # Accessing hostname/port also validates bracket and port syntax.
        hostname = parsed.hostname
        port = parsed.port
        if not hostname:
            return False
        # urlparse validates bracketed IPv6; check DNS labels separately.
        if ':' not in hostname:
            ascii_host = hostname.encode('idna').decode('ascii').rstrip('.')
            if len(ascii_host) > 253 or not all(
                re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in ascii_host.split('.')
            ):
                return False
        return (parsed.scheme.lower() in ('http', 'https')
                and bool(hostname)
                and not any(char in hostname for char in '%/?#@')
                and (port is None or 0 < port <= 65535))
    except (ValueError, UnicodeError):
        return False


@app.route('/model', methods=['GET','POST'])
def my_form_post():
    url = request.form.get('url', '')
    if not is_valid_url(url):
        return jsonify(error='Enter a valid HTTP or HTTPS URL with a hostname.'), 400
    kind_of_url = predict_model(url)
    result = {
        "output": int(kind_of_url)
    }
    result = {str(key): value for key, value in result.items()}
    return jsonify(result=result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
