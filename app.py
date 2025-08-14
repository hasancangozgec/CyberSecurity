# app.py
from flask import Flask, request, jsonify, render_template, Response, stream_with_context
from flask_cors import CORS
import whois
import dns.resolver
import requests
from webtech import WebTech
import subprocess
import json
import time

app = Flask(__name__, static_folder='static', template_folder='.')
CORS(app)

@app.route('/')
def home():
    return render_template('index.html')

def run_analysis_stream(domain, run_nikto):
    # --- 1. ADIM: HIZLI BİTEN PASİF ANALİZLERİ YAP VE GÖNDER ---
    passive_results = {}
    try:
        # Alan adını ve temel bilgileri önce gönderelim
        passive_results['domain'] = domain
        passive_results['whois'] = whois.whois(domain)
        
        dns_records = {}
        record_types = ['A', 'MX', 'TXT', 'NS']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [answer.to_text() for answer in answers]
            except Exception:
                dns_records[record_type] = "Kayıt bulunamadı."
        passive_results['dns'] = dns_records
        
        url = domain if domain.startswith('http') else 'https://' + domain
        response = requests.get(url, timeout=10, headers={'User-Agent': 'PassiveAnalysisTool/1.0'})
        passive_results['headers'] = dict(response.headers)

        wt = WebTech()
        tech_results = wt.start_from_url(url, timeout=10)
        passive_results['tech'] = tech_results

    except Exception as e:
        passive_results['error'] = f"Pasif analiz sırasında bir hata oluştu: {e}"

    # Pasif analiz sonuçlarını JSON formatında tek seferde gönder. 
    # Başına ve sonuna özel bir belirteç ekliyoruz ki JavaScript bunu ayırabilsin.
    yield f"START_PASSIVE_RESULTS\n{json.dumps(passive_results)}\nEND_PASSIVE_RESULTS\n"


    # --- 2. ADIM: UZUN SÜREN NIKTO TARAMASINI BAŞLAT VE LOGLARI ANLIK GÖNDER ---
    if run_nikto:
        yield "\nNikto taraması başlatılıyor...\n"
        yield "===================================\n"
        
        try:
            # Nikto komutunu Popen ile başlatarak anlık çıktı almayı sağlıyoruz
            # stderr'i stdout'a yönlendirerek hem normal çıktıları hem hataları yakalıyoruz
            nikto_command = [
                'perl',
                '/home/ec2-user/CyberSecurity/nikto/program/nikto.pl',
                '-h', domain
            ]
            process = subprocess.Popen(
                nikto_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1 # Satır bazında bufferla
            )

            # Prosesin çıktısını satır satır oku ve anında gönder
            for line in iter(process.stdout.readline, ''):
                yield line
                time.sleep(0.01) # Çok hızlı akışı engellemek için küçük bir bekleme
            
            process.stdout.close()
            return_code = process.wait()
            yield f"\n===================================\n"
            yield f"Nikto taraması tamamlandı. (Çıkış Kodu: {return_code})\n"

        except Exception as e:
            yield f"\nNikto çalıştırılırken bir hata oluştu: {e}\n"

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    domain = data.get('url')
    run_nikto = data.get('run_nikto', False)

    if not domain:
        return Response("Alan adı girilmedi.", status=400)

    # Stream cevabını başlatıyoruz. Her 'yield' tarayıcıya bir veri parçası gönderir.
    return Response(stream_with_context(run_analysis_stream(domain, run_nikto)), mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True)