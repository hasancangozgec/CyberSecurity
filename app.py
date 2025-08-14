# app.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import whois
import dns.resolver
import requests
from webtech import WebTech

# Flask uygulamasını başlatıyoruz
app = Flask(__name__, static_folder='static', template_folder='.')
CORS(app)

# Ana sayfa için bir route. index.html dosyasını sunacak.
@app.route('/')
def home():
    return render_template('index.html')

# Analiz işlemini yapacak ana API endpoint'i
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    domain = data.get('url')

    if not domain:
        return jsonify({'error': 'Alan adı girilmedi.'}), 400

    # Sonuçları toplayacağımız bir sözlük
    results = {}

    # 1. WHOIS Analizi
    try:
        results['whois'] = whois.whois(domain)
    except Exception as e:
        results['whois'] = f"WHOIS bilgisi alınamadı: {e}"

    # 2. DNS Analizi
    try:
        dns_records = {}
        record_types = ['A', 'MX', 'TXT', 'NS']
        for record_type in record_types:
            answers = dns.resolver.resolve(domain, record_type)
            dns_records[record_type] = [answer.to_text() for answer in answers]
        results['dns'] = dns_records
    except Exception as e:
        results['dns'] = f"DNS kayıtları alınamadı: {e}"
        
    # 3. HTTP Headers ve Teknoloji Tespiti
    try:
        # http:// veya https:// yoksa ekle
        url = domain if domain.startswith('http') else 'https://' + domain
        response = requests.get(url, timeout=10, headers={'User-Agent': 'PassiveAnalysisTool/1.0'})
        results['headers'] = dict(response.headers)
        
        # 4. Teknoloji Tespiti
        wt = WebTech()
        tech_results = wt.start_from_url(url, timeout=10)
        results['tech'] = tech_results

    except Exception as e:
        results['headers'] = f"HTTP Başlıkları alınamadı: {e}"
        results['tech'] = "Teknoloji tespiti yapılamadı."


    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)