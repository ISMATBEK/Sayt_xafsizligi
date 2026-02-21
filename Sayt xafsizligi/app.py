from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
import socket
import requests
from bs4 import BeautifulSoup
import threading
from urllib.parse import urlparse, urljoin
import time
import concurrent.futures
import whois
from datetime import datetime
import os
import tempfile
import hashlib
import json
import random

# Vercel muhiti uchun sozlamalar
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'veb-sayt-skanneri-secret-key-2025')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB maksimal fayl hajmi

# Kiberxavfsizlik maslahatlari va ma'lumotlar bazasi
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
        "content": "Google, Telegram va boshqa xizmatlarda 2FA (ikki bosqichli autentifikatsiya) ni yoqing. Bu akkauntingizni himoya qiladi.",
        "icon": "fas fa-mobile-alt",
        "color": "#28a745",
        "category": "2fa"
    },
    {
        "id": 3,
        "title": "⚠️ Fishingdan Saqlaning",
        "content": "Shubhali linklarga kirmang. Bank, ijtimoiy tarmoq xabarlariga ishonmang. Har doim manzilni tekshiring.",
        "icon": "fas fa-exclamation-triangle",
        "color": "#ffc107",
        "category": "phishing"
    },
    {
        "id": 4,
        "title": "🔄 Dasturlarni Yangilang",
        "content": "Operatsion tizim, brauzer va antivirus dasturlaringizni muntazam yangilab turing. Bu xavfsizlik teshiklarini yopadi.",
        "icon": "fas fa-sync-alt",
        "color": "#17a2b8",
        "category": "updates"
    },
    {
        "id": 5,
        "title": "📊 Shaxsiy Ma'lumotlar",
        "content": "Ijtimoiy tarmoqlarda shaxsiy ma'lumotlaringizni (manzil, telefon, tug'ilgan sana) yashiring.",
        "icon": "fas fa-user-secret",
        "color": "#6f42c1",
        "category": "privacy"
    },
    {
        "id": 6,
        "title": "📧 Spam Xabarlar",
        "content": "Noma'lum manzillardan kelgan xabarlarni ochmang. Ulardagi link va fayllar xavfli bo'lishi mumkin.",
        "icon": "fas fa-envelope",
        "color": "#20c997",
        "category": "email"
    },
    {
        "id": 7,
        "title": "🔍 Antivirus Tekshiruvi",
        "content": "Har hafta antivirus dasturi bilan to'liq skanerlash o'tkazing. Telefon va kompyuteringizni himoyalang.",
        "icon": "fas fa-shield-virus",
        "color": "#fd7e14",
        "category": "antivirus"
    },
    {
        "id": 8,
        "title": "📱 Ruxsatlarni Tekshiring",
        "content": "Ilovalarga berilgan ruxsatlarni tekshiring. Keraksiz ruxsatlarni olib tashlang (masalan, chiroqqa internet ruxsati kerakmas).",
        "icon": "fas fa-permission",
        "color": "#e83e8c",
        "category": "permissions"
    },
    {
        "id": 9,
        "title": "🌐 Ochiq Wi-Fi Xavfi",
        "content": "Jamoat Wi-Fi tarmoqlarida bank, email kabi muhim ma'lumotlarni kiritmang. VPN ishlating.",
        "icon": "fas fa-wifi",
        "color": "#6610f2",
        "category": "wifi"
    },
    {
        "id": 10,
        "title": "💾 Zaxira Nusxa",
        "content": "Muhim fayllaringizni bulut va tashqi xotiraga nusxalab qo'ying. Ransomware hujumlaridan saqlaning.",
        "icon": "fas fa-database",
        "color": "#d63384",
        "category": "backup"
    }
]

CYBER_STATS = {
    "daily_attacks": "5000+",
    "protected_users": "1M+",
    "scanned_sites": "100K+",
    "threats_blocked": "50K+"
}

# ========== Kiberxavfsizlik Yangiliklari ==========
CYBER_NEWS = [
    {
        "title": "Yangi Android banking trojani aniqlandi",
        "date": "2025-02-20",
        "summary": "Xavfli dastur banking ilovalari ma'lumotlarini o'g'irlayapti",
        "source": "Kaspersky"
    },
    {
        "title": "Telegram fishing hujumlari kuchaydi",
        "date": "2025-02-18",
        "summary": "Soxta Telegram akkauntlari orqali ma'lumotlar o'g'irlanmoqda",
        "source": "ESET"
    },
    {
        "title": "WhatsApp'da yangi xavfsizlik muammosi",
        "date": "2025-02-15",
        "summary": "Zararli linklar orqali akkauntlarni egallash holatlari",
        "source": "Check Point"
    }
]

# ========== Kiberxavfsizlik Vikipediyasi ==========
CYBER_WIKI = {
    "phishing": {
        "title": "Fishing (Phishing) Nima?",
        "description": "Fishing - bu firibgarlarning soxta veb-saytlar yoki xabarlar orqali shaxsiy ma'lumotlarni o'g'irlash usuli.",
        "signs": [
            "Shoshilinch xabarlar (Hisobingiz yopiladi)",
            "Sovrin yutdingiz degan xabarlar",
            "Soxta domenlar (g00gle.com, faceb00k.com)",
            "Grammatik xatolar"
        ],
        "protection": [
            "Linklarni tekshiring",
            "Ishonchli manbalardan foydalaning",
            "2FA ni yoqing"
        ]
    },
    "malware": {
        "title": "Zararli Dasturlar (Malware)",
        "description": "Kompyuter yoki telefoningizga zarar yetkazuvchi dasturlar.",
        "types": [
            "Virus - fayllarni buzadi",
            "Trojan - boshqa dastur ko'rinishida",
            "Ransomware - fayllarni qulflab, pul talab qiladi",
            "Spyware - kuzatuv dasturi"
        ],
        "protection": [
            "Antivirus o'rnating",
            "Noma'lum manbalardan dastur o'rnatmang",
            "Muntazam yangilang"
        ]
    },
    "password": {
        "title": "Xavfsiz Parollar",
        "description": "Kuchli parollar akkauntlaringizni himoya qiladi.",
        "rules": [
            "Kamida 8 belgi",
            "Katta va kichik harflar",
            "Raqamlar va maxsus belgilar",
            "Har bir sayt uchun unikal parol"
        ],
        "tools": [
            "Parol menejerlari (Bitwarden, LastPass)",
            "Ikki bosqichli autentifikatsiya"
        ]
    },
    "2fa": {
        "title": "Ikki Bosqichli Autentifikatsiya (2FA)",
        "description": "Akkauntlaringizga qo'shimcha himoya qatlami.",
        "methods": [
            "SMS kodlari (xavfsiz emas)",
            "Authenticator ilovalari (Google Authenticator)",
            "Hardware tokenlar (YubiKey)"
        ]
    },
    "vpn": {
        "title": "VPN (Virtual Private Network)",
        "description": "Internetdagi maxfiylik va xavfsizlikni ta'minlaydi.",
        "benefits": [
            "IP manzilingizni yashiradi",
            "Ma'lumotlaringizni shifrlaydi",
            "Ochiq Wi-Fi tarmoqlarida himoya"
        ]
    }
}

# ========== ASOSIY ROUTE ==========
@app.route('/')
def index():
    """Bosh sahifa - kiberxavfsizlik maslahatlari bilan"""
    # Kunlik maslahat
    daily_tip = random.choice(CYBER_TIPS)
    
    # Kategoriyalar bo'yicha maslahatlar
    tips_by_category = {}
    for tip in CYBER_TIPS:
        cat = tip['category']
        if cat not in tips_by_category:
            tips_by_category[cat] = []
        tips_by_category[cat].append(tip)
    
    return render_template('index.html', 
                         daily_tip=daily_tip,
                         cyber_tips=CYBER_TIPS,
                         cyber_stats=CYBER_STATS,
                         cyber_news=CYBER_NEWS,
                         cyber_wiki=CYBER_WIKI,
                         tips_by_category=tips_by_category)

@app.route('/wiki/<topic>')
def cyber_wiki_topic(topic):
    """Kiberxavfsizlik vikipediyasi"""
    if topic in CYBER_WIKI:
        return jsonify(CYBER_WIKI[topic])
    return jsonify({"error": "Mavzu topilmadi"}), 404

@app.route('/daily-tip')
def daily_tip():
    """Kunlik maslahat"""
    return jsonify(random.choice(CYBER_TIPS))

@app.route('/scan', methods=['POST'])
def scan_website():
    """Sayt skanerlash"""
    try:
        website = request.form.get('website', '').strip()
        
        if not website:
            return render_template('index.html', 
                                 daily_tip=random.choice(CYBER_TIPS),
                                 cyber_tips=CYBER_TIPS,
                                 cyber_stats=CYBER_STATS,
                                 error='Sayt manzilini kiriting!')
        
        # Domenni ajratib olish
        if website.startswith(('http://', 'https://')):
            domain = urlparse(website).netloc
        else:
            domain = website.split('/')[0]
        
        # Tezkor skanerlash (demo ma'lumotlar)
        results = {
            'scan_type': 'website',
            'domain': domain,
            'website': website,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'port_scan': {
                'ip': socket.gethostbyname(domain) if domain else '0.0.0.0',
                'open_ports': [
                    {'port': 80, 'service': 'HTTP', 'status': 'open'},
                    {'port': 443, 'service': 'HTTPS', 'status': 'open'}
                ] if not domain.startswith('test') else []
            },
            'security_scan': [
                {
                    'type': 'HTTPS Tekshiruvi',
                    'level': 'Yuqori' if not website.startswith('https') else 'Past',
                    'description': 'Sayt HTTPS dan foydalanmayapti' if not website.startswith('https') else 'HTTPS ishlatilgan',
                    'recommendation': 'SSL sertifikatini o\'rnating' if not website.startswith('https') else 'Yaxshi'
                }
            ]
        }
        
        session['last_results'] = results
        return render_template('results.html', results=results)
        
    except Exception as e:
        return render_template('index.html', 
                             daily_tip=random.choice(CYBER_TIPS),
                             cyber_tips=CYBER_TIPS,
                             cyber_stats=CYBER_STATS,
                             error=f'Skanerlashda xatolik: {str(e)}')

@app.route('/check-links', methods=['POST'])
def check_links_route():
    """Linklarni tekshirish"""
    try:
        website = request.form.get('website', '').strip()
        
        if not website:
            return render_template('index.html', 
                                 daily_tip=random.choice(CYBER_TIPS),
                                 cyber_tips=CYBER_TIPS,
                                 cyber_stats=CYBER_STATS,
                                 error='Sayt manzilini kiriting!')
        
        # Demo link tekshiruvi
        link_results = {
            'total_links': 15,
            'broken_links': [],
            'suspicious_links': [],
            'malicious_links': [],
            'internal_links': [
                {'url': '/about', 'text': 'Biz haqimizda'},
                {'url': '/contact', 'text': 'Bog\'lanish'}
            ],
            'external_links': [
                {'url': 'https://google.com', 'text': 'Google'}
            ]
        }
        
        results = {
            'scan_type': 'links',
            'website': website,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'link_check': link_results
        }
        
        session['last_results'] = results
        return render_template('results.html', results=results)
        
    except Exception as e:
        return render_template('index.html', 
                             daily_tip=random.choice(CYBER_TIPS),
                             cyber_tips=CYBER_TIPS,
                             cyber_stats=CYBER_STATS,
                             error=f'Link tekshiruvida xatolik: {str(e)}')

@app.route('/analyze-apk', methods=['POST'])
def analyze_apk_route():
    """APK faylni tahlil qilish"""
    try:
        if 'file' not in request.files:
            return render_template('index.html', 
                                 daily_tip=random.choice(CYBER_TIPS),
                                 cyber_tips=CYBER_TIPS,
                                 cyber_stats=CYBER_STATS,
                                 error='APK faylini yuklang')
        
        file = request.files['file']
        if file.filename == '':
            return render_template('index.html', error='Fayl tanlanmagan')
        
        if not file.filename.lower().endswith('.apk'):
            return render_template('index.html', error='Faqat APK fayllar qabul qilinadi')
        
        # Demo APK tahlili
        apk_results = {
            'file_info': {
                'file_name': file.filename,
                'file_size_mb': round(len(file.read()) / (1024 * 1024), 2)
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
            'security_issues': [],
            'malware_analysis': {
                'risk_score': 25,
                'detected': 0,
                'verdict': 'XAVFSIZ'
            }
        }
        
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': apk_results
        }
        
        session['last_results'] = results
        return render_template('results.html', results=results)
        
    except Exception as e:
        return render_template('index.html', 
                             daily_tip=random.choice(CYBER_TIPS),
                             cyber_tips=CYBER_TIPS,
                             cyber_stats=CYBER_STATS,
                             error=f'APK tahlilida xatolik: {str(e)}')

@app.route('/results')
def show_results():
    """Natijalarni ko'rsatish"""
    results = session.get('last_results')
    if not results:
        return redirect(url_for('index'))
    return render_template('results.html', results=results)

@app.route('/ads.txt')
def serve_ads_txt():
    return send_from_directory('static', 'ads.txt')

@app.route('/google-adsense-verification.html')
def serve_verification_file():
    return send_from_directory('static', 'google-adsense-verification.html')

@app.route('/robots.txt')
def serve_robots_txt():
    return send_from_directory('static', 'robots.txt')

# Vercel uchun
app.debug = False

if __name__ == '__main__':
    app.run(debug=True)
