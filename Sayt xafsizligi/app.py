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
import string

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cyberdash-secret-key-2025')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

# ========== MA'LUMOTLAR BAZASI ==========

# Kiberxavfsizlik maslahatlari
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

# Kiberxavfsizlik vikipediyasi
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
    },
    "2fa": {
        "title": "Ikki Bosqichli Autentifikatsiya",
        "description": "Hisobingizga qo'shimcha himoya qatlami qo'shish usuli.",
        "methods": [
            "SMS kodlari",
            "Authenticator ilovalari",
            "Hardware tokenlar"
        ]
    },
    "vpn": {
        "title": "VPN (Virtual Private Network)",
        "description": "Internetdagi maxfiylik va xavfsizlikni ta'minlaydi.",
        "benefits": [
            "IP manzilingizni yashiradi",
            "Ma'lumotlaringizni shifrlaydi",
            "Ochiq Wi-Fi tarmoqlarida himoya qiladi"
        ]
    }
}

# Kurslar
COURSES = [
    {
        "id": 1,
        "title": "Kiberxavfsizlik asoslari",
        "description": "Boshlang'ich daraja uchun kiberxavfsizlik asoslari",
        "lessons": 10,
        "duration": "5 soat",
        "level": "Boshlang'ich",
        "image": "fas fa-shield-alt",
        "color": "#667eea"
    },
    {
        "id": 2,
        "title": "Xavfsiz dasturlash",
        "description": "Xavfsiz kod yozish amaliyotlari",
        "lessons": 15,
        "duration": "8 soat",
        "level": "O'rta",
        "image": "fas fa-code",
        "color": "#f59e0b"
    },
    {
        "id": 3,
        "title": "Penetration Testing",
        "description": "Professional penetration testing usullari",
        "lessons": 20,
        "duration": "12 soat",
        "level": "Yuqori",
        "image": "fas fa-bug",
        "color": "#ef4444"
    }
]

# ========== KONTEKST PROCESSOR ==========
@app.context_processor
def utility_processor():
    return {
        'now': datetime.datetime.now(),
        'app_name': 'CyberDash',
        'app_version': '1.0.0'
    }

# ========== ASOSIY ROUTES ==========

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

@app.route('/cyber-quiz')
def cyber_quiz():
    """Kiberxavfsizlik testi"""
    return render_template('cyber_quiz.html', active_page='cyber_quiz')

@app.route('/password-generator')
def password_generator():
    """Parol generator"""
    return render_template('password_generator.html', active_page='password_generator')

@app.route('/courses')
def courses():
    """Kurslar"""
    return render_template('courses.html', courses=COURSES, active_page='courses')

@app.route('/profile')
def profile():
    """Shaxsiy kabinet"""
    return render_template('profile.html', active_page='profile')

@app.route('/settings')
def settings():
    """Sozlamalar"""
    return render_template('settings.html', active_page='settings')

@app.route('/help')
def help():
    """Yordam"""
    return render_template('help.html', active_page='help')

# ========== SCANNER ROUTES ==========

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
        
        # Hash hisoblash
        md5_hash = hashlib.md5(file_data).hexdigest()
        
        # Demo APK tahlili
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': {
                'file_info': {
                    'file_name': file.filename,
                    'file_size_mb': round(file_size, 2),
                    'md5_hash': md5_hash[:16] + '...'
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

# ========== API ROUTES ==========

@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    """Parol generatsiya qilish API"""
    try:
        data = request.json
        length = int(data.get('length', 12))
        use_upper = data.get('use_upper', True)
        use_lower = data.get('use_lower', True)
        use_numbers = data.get('use_numbers', True)
        use_symbols = data.get('use_symbols', True)
        
        chars = ''
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_numbers:
            chars += string.digits
        if use_symbols:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Parol kuchini hisoblash
        strength = 0
        if length >= 12:
            strength += 25
        elif length >= 8:
            strength += 15
        else:
            strength += 5
            
        if use_upper and use_lower:
            strength += 25
        if use_numbers:
            strength += 25
        if use_symbols:
            strength += 25
            
        strength_text = 'Kuchsiz' if strength < 40 else 'O\'rtacha' if strength < 70 else 'Kuchli'
        
        return jsonify({
            'success': True,
            'password': password,
            'strength': strength,
            'strength_text': strength_text
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/check-password-strength', methods=['POST'])
def check_password_strength():
    """Parol kuchini tekshirish"""
    try:
        data = request.json
        password = data.get('password', '')
        
        strength = 0
        feedback = []
        
        # Uzunlik
        if len(password) >= 12:
            strength += 30
        elif len(password) >= 8:
            strength += 20
        elif len(password) >= 6:
            strength += 10
        else:
            feedback.append("Parol juda qisqa (kamida 8 belgi)")
        
        # Katta harf
        if any(c.isupper() for c in password):
            strength += 20
        else:
            feedback.append("Katta harf qo'shing")
        
        # Kichik harf
        if any(c.islower() for c in password):
            strength += 20
        else:
            feedback.append("Kichik harf qo'shing")
        
        # Raqam
        if any(c.isdigit() for c in password):
            strength += 15
        else:
            feedback.append("Raqam qo'shing")
        
        # Maxsus belgi
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            strength += 15
        else:
            feedback.append("Maxsus belgi qo'shing")
        
        strength_text = 'Kuchsiz' if strength < 40 else 'O\'rtacha' if strength < 70 else 'Kuchli'
        
        return jsonify({
            'success': True,
            'strength': strength,
            'strength_text': strength_text,
            'feedback': feedback
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/cyber-tip')
def get_cyber_tip():
    """Kunlik maslahat olish"""
    return jsonify(random.choice(CYBER_TIPS))

@app.route('/api/wiki/<topic>')
def get_wiki_topic(topic):
    """Wiki mavzusini olish"""
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

# ========== ERROR HANDLERS ==========

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large_error(error):
    return jsonify({'error': 'Fayl hajmi juda katta!'}), 413

# ========== VERCEL SOZLAMALARI ==========
app.debug = False

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
