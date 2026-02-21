from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import datetime
import os
import hashlib
import random
import json

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cyberdash-secret-key-2025')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

# ========== Kiberxavfsizlik ma'lumotlar bazasi ==========
CYBER_TIPS = [
    {
        "id": 1,
        "title": "🔐 Kuchli Parollar",
        "content": "Har bir akkaunt uchun unikal va murakkab parol ishlating. Parollarda katta-kichik harflar, raqamlar va maxsus belgilar bo'lsin.",
        "icon": "fas fa-lock",
        "color": "#dc3545",
        "category": "password"
    },
    {
        "id": 2,
        "title": "📱 Ikki Bosqichli Autentifikatsiya",
        "content": "Google, Telegram va boshqa xizmatlarda 2FA (ikki bosqichli autentifikatsiya) ni yoqing.",
        "icon": "fas fa-mobile-alt",
        "color": "#28a745",
        "category": "2fa"
    },
    {
        "id": 3,
        "title": "⚠️ Fishingdan Saqlaning",
        "content": "Shubhali linklarga kirmang. Bank, ijtimoiy tarmoq xabarlariga ishonmang.",
        "icon": "fas fa-exclamation-triangle",
        "color": "#ffc107",
        "category": "phishing"
    },
    {
        "id": 4,
        "title": "🔄 Dasturlarni Yangilang",
        "content": "Operatsion tizim, brauzer va antivirus dasturlaringizni muntazam yangilab turing.",
        "icon": "fas fa-sync-alt",
        "color": "#17a2b8",
        "category": "updates"
    },
    {
        "id": 5,
        "title": "🌐 Ochiq Wi-Fi Xavfi",
        "content": "Jamoat Wi-Fi tarmoqlarida bank, email kabi muhim ma'lumotlarni kiritmang. VPN ishlating.",
        "icon": "fas fa-wifi",
        "color": "#6610f2",
        "category": "wifi"
    }
]

CYBER_WIKI = {
    "phishing": {
        "title": "Fishing (Phishing)",
        "description": "Fishing - bu firibgarlarning soxta veb-saytlar yoki xabarlar orqali shaxsiy ma'lumotlarni o'g'irlash usuli.",
        "signs": [
            "Shoshilinch xabarlar (Hisobingiz yopiladi)",
            "Sovrin yutdingiz degan xabarlar",
            "Soxta domenlar (g00gle.com)",
            "Grammatik xatolar"
        ],
        "protection": [
            "Linklarni tekshiring",
            "Ishonchli manbalardan foydalaning",
            "2FA ni yoqing"
        ]
    },
    "malware": {
        "title": "Zararli Dasturlar",
        "description": "Kompyuter yoki telefoningizga zarar yetkazuvchi dasturlar.",
        "types": [
            "Virus - fayllarni buzadi",
            "Trojan - boshqa dastur ko'rinishida",
            "Ransomware - fayllarni qulflab, pul talab qiladi"
        ],
        "protection": [
            "Antivirus o'rnating",
            "Noma'lum manbalardan dastur o'rnatmang"
        ]
    }
}

# ========== ROUTES ==========

@app.route('/')
def index():
    """Bosh sahifa"""
    daily_tip = random.choice(CYBER_TIPS)
    return render_template('index.html', 
                         daily_tip=daily_tip,
                         cyber_tips=CYBER_TIPS,
                         active_page='home')

@app.route('/scanner')
def scanner():
    """Website scanner sahifasi"""
    return render_template('scanner.html', active_page='scanner')

@app.route('/link-checker')
def link_checker():
    """Link checker sahifasi"""
    return render_template('link_checker.html', active_page='link_checker')

@app.route('/apk-analyzer')
def apk_analyzer():
    """APK analyzer sahifasi"""
    return render_template('apk_analyzer.html', active_page='apk_analyzer')

@app.route('/cyber-tips')
def cyber_tips():
    """Kiberxavfsizlik maslahatlari"""
    return render_template('cyber_tips.html', 
                         cyber_tips=CYBER_TIPS,
                         active_page='cyber_tips')

@app.route('/cyber-wiki')
def cyber_wiki():
    """Kiberxavfsizlik vikipediyasi"""
    return render_template('cyber_wiki.html', 
                         cyber_wiki=CYBER_WIKI,
                         active_page='cyber_wiki')

@app.route('/scan-website', methods=['POST'])
def scan_website():
    """Saytni skanerlash"""
    try:
        website = request.form.get('website', '').strip()
        
        if not website:
            return jsonify({'error': 'Sayt manzilini kiriting!'})
        
        # Domainni ajratish
        if website.startswith(('http://', 'https://')):
            domain = urlparse(website).netloc
        else:
            domain = website.split('/')[0]
        
        # Demo skanerlash natijalari
        results = {
            'scan_type': 'website',
            'domain': domain,
            'website': website,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'security_scan': [
                {
                    'type': 'HTTPS Tekshiruvi',
                    'level': 'Yuqori' if not website.startswith('https') else 'Past',
                    'description': 'Sayt HTTPS dan foydalanmayapti. Ma\'lumotlar shifrlanmayapti!' if not website.startswith('https') else 'HTTPS ishlatilgan. Xavfsiz ulanish.',
                    'recommendation': 'SSL sertifikatini o\'rnating va HTTPS ga o\'tishingiz kerak' if not website.startswith('https') else 'Yaxshi, HTTPS ishlatilyapti'
                },
                {
                    'type': 'Server Ma\'lumoti',
                    'level': 'O\'rta',
                    'description': 'Server: nginx/1.18.0',
                    'recommendation': 'Server versiyasini yashirishingiz tavsiya etiladi'
                }
            ]
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/check-links', methods=['POST'])
def check_links():
    """Linklarni tekshirish"""
    try:
        website = request.form.get('website', '').strip()
        
        if not website:
            return jsonify({'error': 'Sayt manzilini kiriting!'})
        
        # Demo link tekshiruvi
        results = {
            'scan_type': 'links',
            'website': website,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'link_check': {
                'total_links': 15,
                'broken_links': [],
                'internal_links': [
                    {'url': '/about', 'text': 'Biz haqimizda'},
                    {'url': '/contact', 'text': 'Bog\'lanish'}
                ],
                'external_links': [
                    {'url': 'https://google.com', 'text': 'Google'}
                ]
            }
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/analyze-apk', methods=['POST'])
def analyze_apk():
    """APK faylni tahlil qilish"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'APK faylini yuklang!'})
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'Fayl tanlanmagan!'})
        
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'Faqat .apk fayllar qabul qilinadi!'})
        
        # Faylni o'qish
        file_data = file.read()
        file_size = len(file_data) / (1024 * 1024)  # MB
        
        if file_size > 10:
            return jsonify({'error': 'Fayl hajmi 10MB dan katta!'})
        
        # Demo APK tahlili
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': {
                'file_info': {
                    'file_name': file.filename,
                    'file_size_mb': round(file_size, 2)
                },
                'permissions': [
                    {
                        'name': 'Internet',
                        'risk': 'PAST',
                        'description': 'Internetga ulanish imkoniyati'
                    },
                    {
                        'name': 'Read Contacts',
                        'risk': 'O\'RTA',
                        'description': 'Kontaktlarni o\'qish'
                    }
                ],
                'malware_analysis': {
                    'risk_score': random.randint(10, 90),
                    'detected': random.randint(0, 2),
                    'verdict': random.choice(['XAVFSIZ', 'SHAXBILI', 'XAVFLI'])
                }
            }
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/results')
def results():
    """Natijalarni ko'rsatish"""
    results = session.get('last_results')
    if not results:
        return redirect(url_for('index'))
    return render_template('results.html', results=results, active_page='results')

@app.route('/wiki/<topic>')
def wiki_topic(topic):
    """Wiki mavzusini qaytarish"""
    if topic in CYBER_WIKI:
        return jsonify(CYBER_WIKI[topic])
    return jsonify({'error': 'Mavzu topilmadi'}), 404

# ========== STATIC FILES ==========
@app.route('/ads.txt')
def serve_ads_txt():
    return send_from_directory('static', 'ads.txt')

@app.route('/google-adsense-verification.html')
def serve_verification_file():
    return send_from_directory('static', 'google-adsense-verification.html')

@app.route('/robots.txt')
def serve_robots_txt():
    return send_from_directory('static', 'robots.txt')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
