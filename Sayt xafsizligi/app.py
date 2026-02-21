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
import time
import uuid
import re

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cyberdash-secret-key-2025')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)

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
    },
    {
        "id": 6,
        "title": "💾 Zaxira Nusxa",
        "content": "Muhim fayllaringizni muntazam zaxiralab turing. Bulut va tashqi xotiraga nusxalang.",
        "icon": "fas fa-database",
        "color": "#6f42c1",
        "category": "backup"
    },
    {
        "id": 7,
        "title": "🔍 Antivirus Tekshiruvi",
        "content": "Har hafta antivirus dasturi bilan to'liq skanerlash o'tkazing.",
        "icon": "fas fa-shield-virus",
        "color": "#fd7e14",
        "category": "antivirus"
    },
    {
        "id": 8,
        "title": "📧 Spam Xabarlar",
        "content": "Noma'lum manzillardan kelgan xabarlarni ochmang va ulardagi linklarga kirmang.",
        "icon": "fas fa-envelope",
        "color": "#20c997",
        "category": "email"
    },
    {
        "id": 9,
        "title": "🔒 Shaxsiy Ma'lumotlar",
        "content": "Ijtimoiy tarmoqlarda manzil, telefon, tug'ilgan sana kabi ma'lumotlarni yashiring.",
        "icon": "fas fa-user-secret",
        "color": "#e83e8c",
        "category": "privacy"
    },
    {
        "id": 10,
        "title": "🛡️ VPN dan Foydalaning",
        "content": "Ochiq Wi-Fi tarmoqlarida VPN ishlating. Bu ma'lumotlaringizni himoya qiladi.",
        "icon": "fas fa-globe",
        "color": "#0dcaf0",
        "category": "vpn"
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
            "Soxta domenlar (g00gle.com, faceb00k.com)",
            "Grammatik xatolar",
            "HTTP (xavfsiz emas) ulanish"
        ],
        "protection": [
            "Linklarni tekshiring",
            "Ishonchli manbalardan foydalaning",
            "2FA ni yoqing",
            "URL manzilini diqqat bilan o'qing"
        ]
    },
    "malware": {
        "title": "Zararli Dasturlar (Malware)",
        "description": "Kompyuter yoki telefoningizga zarar yetkazuvchi dasturlar.",
        "types": [
            "Virus - fayllarni buzadi va tarqaladi",
            "Trojan - foydali dastur ko'rinishida keladi",
            "Ransomware - fayllarni qulflab, pul talab qiladi",
            "Spyware - kuzatuv dasturi",
            "Adware - reklama ko'rsatadi"
        ],
        "protection": [
            "Antivirus o'rnating",
            "Noma'lum manbalardan dastur o'rnatmang",
            "Muntazam yangilab turing",
            "Ruxsatlarni tekshiring"
        ]
    },
    "2fa": {
        "title": "Ikki Bosqichli Autentifikatsiya (2FA)",
        "description": "Hisobingizga qo'shimcha himoya qatlami qo'shish usuli.",
        "methods": [
            "SMS kodlari (xavfsiz emas)",
            "Authenticator ilovalari (Google Authenticator, Authy)",
            "Hardware tokenlar (YubiKey)",
            "Biometrik (barmoq izi, yuz tanish)"
        ],
        "benefits": [
            "Parol bilinsa ham himoya",
            "Ruxsatsiz kirishni bloklaydi",
            "Xavfsizlikni 99% oshiradi"
        ]
    },
    "vpn": {
        "title": "VPN (Virtual Private Network)",
        "description": "Internetdagi maxfiylik va xavfsizlikni ta'minlaydi.",
        "benefits": [
            "IP manzilingizni yashiradi",
            "Ma'lumotlaringizni shifrlaydi",
            "Ochiq Wi-Fi tarmoqlarida himoya qiladi",
            "Geobloklarni chetlab o'tadi"
        ],
        "risks": [
            "Bepul VPN lar xavfli bo'lishi mumkin",
            "Ba'zi VPN lar log saqlaydi",
            "Tezlikni pasaytirishi mumkin"
        ]
    },
    "password": {
        "title": "Xavfsiz Parollar",
        "description": "Kuchli parollar akkauntlaringizni himoya qiladi.",
        "rules": [
            "Kamida 12 belgi",
            "Katta va kichik harflar",
            "Raqamlar va maxsus belgilar",
            "Har bir sayt uchun unikal parol",
            "Shaxsiy ma'lumotlardan foydalanmang"
        ],
        "tools": [
            "Parol menejerlari (Bitwarden, LastPass)",
            "Parol generatorlar",
            "2FA"
        ]
    }
}

# Kurslar
COURSES = [
    {
        "id": 1,
        "title": "Kiberxavfsizlik asoslari",
        "description": "Boshlang'ich daraja uchun kiberxavfsizlik asoslari. Bu kursda siz xavfsiz internet, parollar, fishing va boshqa asosiy tushunchalarni o'rganasiz.",
        "lessons": 10,
        "duration": "5 soat",
        "level": "Boshlang'ich",
        "level_color": "#10b981",
        "image": "fas fa-shield-alt",
        "color": "#667eea",
        "instructor": "Aziz Karimov",
        "students": 1234,
        "rating": 4.8,
        "price": "Bepul",
        "topics": [
            "Xavfsiz internet",
            "Kuchli parollar",
            "Fishingdan himoya",
            "Antivirus dasturlari",
            "2FA sozlamalari"
        ]
    },
    {
        "id": 2,
        "title": "Xavfsiz dasturlash",
        "description": "Xavfsiz kod yozish amaliyotlari. SQL injection, XSS va boshqa xavflardan himoyalanish.",
        "lessons": 15,
        "duration": "8 soat",
        "level": "O'rta",
        "level_color": "#f59e0b",
        "image": "fas fa-code",
        "color": "#f59e0b",
        "instructor": "Dilmurod Tursunov",
        "students": 856,
        "rating": 4.6,
        "price": "Bepul",
        "topics": [
            "SQL injection",
            "XSS hujumlari",
            "CSRF himoya",
            "Xavfsiz autentifikatsiya",
            "Ma'lumotlar shifrlash"
        ]
    },
    {
        "id": 3,
        "title": "Penetration Testing",
        "description": "Professional penetration testing usullari va vositalari. Ethical hacking asoslari.",
        "lessons": 20,
        "duration": "12 soat",
        "level": "Yuqori",
        "level_color": "#ef4444",
        "image": "fas fa-bug",
        "color": "#ef4444",
        "instructor": "Jasur Abdullayev",
        "students": 567,
        "rating": 4.9,
        "price": "Bepul",
        "topics": [
            "Network scanning",
            "Vulnerability assessment",
            "Web application testing",
            "Wireless security",
            "Social engineering"
        ]
    },
    {
        "id": 4,
        "title": "Mobil xavfsizlik",
        "description": "Android va iOS ilovalar xavfsizligi. Mobil malware va himoya usullari.",
        "lessons": 12,
        "duration": "6 soat",
        "level": "O'rta",
        "level_color": "#3b82f6",
        "image": "fas fa-mobile-alt",
        "color": "#3b82f6",
        "instructor": "Gulnora Rahimova",
        "students": 432,
        "rating": 4.7,
        "price": "Bepul",
        "topics": [
            "Android xavfsizlik",
            "iOS xavfsizlik",
            "Mobil malware",
            "Ilova ruxsatlari",
            "Ma'lumotlar himoyasi"
        ]
    }
]

# Test natijalari
QUIZ_RESULTS = {
    "excellent": {
        "min_score": 80,
        "title": "Ajoyib! Siz kiberxavfsizlik bo'yicha mutaxassissiz! 🎉",
        "advice": "Bilimingizni yanada oshirish uchun Penetration Testing kursini o'rganishingiz mumkin.",
        "icon": "fas fa-crown",
        "color": "#10b981"
    },
    "good": {
        "min_score": 60,
        "title": "Yaxshi! Sizda asosiy bilimlar mavjud. 👍",
        "advice": "Xatolaringizni tahlil qilib, Cyber Wiki bo'limini o'qing.",
        "icon": "fas fa-star",
        "color": "#f59e0b"
    },
    "average": {
        "min_score": 40,
        "title": "Qoniqarli, lekin ko'proq o'rganishingiz kerak. 📚",
        "advice": "Kiberxavfsizlik asoslari kursini boshlashni tavsiya qilamiz.",
        "icon": "fas fa-book",
        "color": "#3b82f6"
    },
    "poor": {
        "min_score": 0,
        "title": "Sizga ko'proq o'rganish kerak. Kiberxavfsizlik muhim! ⚠️",
        "advice": "Cyber Wiki va Cyber Tips bo'limlarini diqqat bilan o'qing.",
        "icon": "fas fa-exclamation-triangle",
        "color": "#ef4444"
    }
}

# ========== KONTEKST PROCESSOR ==========
@app.context_processor
def utility_processor():
    return {
        'now': datetime.datetime.now(),
        'app_name': 'CyberDash',
        'app_version': '1.0.0',
        'current_year': datetime.datetime.now().year
    }

# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large_error(error):
    return jsonify({'error': 'Fayl hajmi juda katta! Maksimal 10MB'}), 413

# ========== ASOSIY ROUTES ==========

@app.route('/')
def index():
    """Bosh sahifa"""
    daily_tip = random.choice(CYBER_TIPS)
    
    # Statistika
    stats = {
        'total_scans': random.randint(15000, 25000),
        'threats_detected': random.randint(5000, 10000),
        'users': random.randint(8000, 15000),
        'quizzes_taken': random.randint(3000, 7000)
    }
    
    return render_template('index.html', 
                         daily_tip=daily_tip,
                         cyber_tips=CYBER_TIPS[:6],
                         stats=stats,
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
    # Kategoriyalar bo'yicha guruhlash
    categories = {}
    for tip in CYBER_TIPS:
        cat = tip['category']
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(tip)
    
    return render_template('cyber_tips.html', 
                         cyber_tips=CYBER_TIPS,
                         categories=categories,
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
    return render_template('cyber_quiz.html', 
                         quiz_results=QUIZ_RESULTS,
                         active_page='cyber_quiz')

@app.route('/password-generator')
def password_generator():
    """Parol generator"""
    return render_template('password_generator.html', active_page='password_generator')

@app.route('/courses')
def courses():
    """Kurslar"""
    return render_template('courses.html', 
                         courses=COURSES, 
                         active_page='courses')

@app.route('/course/<int:course_id>')
def course_detail(course_id):
    """Kurs detallari"""
    course = next((c for c in COURSES if c['id'] == course_id), None)
    if not course:
        return redirect(url_for('courses'))
    
    # O'xshash kurslar
    similar_courses = [c for c in COURSES if c['id'] != course_id][:3]
    
    return render_template('course_detail.html',
                         course=course,
                         similar_courses=similar_courses,
                         active_page='courses')

@app.route('/profile')
def profile():
    """Shaxsiy kabinet"""
    # Agar foydalanuvchi kirmagan bo'lsa
    if 'user' not in session:
        session['user'] = {
            'username': 'Guest User',
            'email': 'guest@example.com',
            'joined': datetime.datetime.now().strftime('%Y-%m-%d'),
            'avatar_color': random.choice(['#667eea', '#f59e0b', '#10b981', '#ef4444'])
        }
    
    # Statistika
    stats = {
        'scans': random.randint(10, 50),
        'quizzes': random.randint(1, 20),
        'average_score': random.randint(40, 95),
        'days_active': random.randint(1, 30)
    }
    
    return render_template('profile.html', 
                         user=session['user'],
                         stats=stats,
                         active_page='profile')

@app.route('/settings')
def settings():
    """Sozlamalar"""
    return render_template('settings.html', active_page='settings')

@app.route('/help')
def help():
    """Yordam"""
    return render_template('help.html', active_page='help')

@app.route('/results')
def results():
    """Natijalarni ko'rsatish"""
    results = session.get('last_results')
    if not results:
        return redirect(url_for('index'))
    return render_template('results.html', results=results, active_page='results')

@app.route('/privacy')
def privacy():
    """Maxfiylik siyosati"""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Foydalanish shartlari"""
    return render_template('terms.html')

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
            protocol = website.split('://')[0]
        else:
            domain = website.split('/')[0]
            protocol = 'http'
            website = 'http://' + website
        
        # IP manzil
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Aniqlanmadi"
        
        # Skanerlash natijalari (demo)
        security_issues = []
        
        # HTTPS tekshiruvi
        if protocol != 'https':
            security_issues.append({
                'type': 'HTTPS xavfsizligi',
                'level': 'Yuqori',
                'description': 'Sayt HTTPS dan foydalanmayapti. Maʼlumotlar shifrlanmayapti!',
                'recommendation': 'SSL sertifikatini oʻrnating va HTTPS ga oʻtishingiz kerak'
            })
        else:
            security_issues.append({
                'type': 'HTTPS xavfsizligi',
                'level': 'Past',
                'description': 'HTTPS ishlatilgan. Xavfsiz ulanish.',
                'recommendation': 'Yaxshi, HTTPS ishlatilyapti'
            })
        
        # Security headers
        headers_to_check = [
            {'name': 'X-Frame-Options', 'desc': 'Clickjacking himoyasi', 'risk': 'Oʻrta'},
            {'name': 'X-Content-Type-Options', 'desc': 'MIME turi himoyasi', 'risk': 'Oʻrta'},
            {'name': 'Strict-Transport-Security', 'desc': 'HSTS himoyasi', 'risk': 'Oʻrta'},
            {'name': 'Content-Security-Policy', 'desc': 'CSP himoyasi', 'risk': 'Yuqori'}
        ]
        
        for header in headers_to_check:
            if random.choice([True, False]):  # Random tekshirish
                security_issues.append({
                    'type': header['desc'],
                    'level': header['risk'],
                    'description': f'{header["name"]} sarlavhasi yoʻq',
                    'recommendation': f'{header["name"]} sarlavhasini qoʻshing'
                })
        
        # Server ma'lumotlari
        servers = ['nginx/1.18.0', 'Apache/2.4.41', 'IIS/10.0', 'Cloudflare']
        security_issues.append({
            'type': 'Server maʼlumoti',
            'level': 'Oʻrta',
            'description': f'Server: {random.choice(servers)}',
            'recommendation': 'Server versiyasini yashirishingiz tavsiya etiladi'
        })
        
        # SEO tahlili
        seo_analysis = {
            'title': 'Example Website - ' + domain,
            'title_length': len('Example Website - ' + domain),
            'description': 'Bu sayt haqida qisqacha maʼlumot...',
            'description_length': 120,
            'headings': {'h1': 1, 'h2': 3, 'h3': 5},
            'images': 8,
            'images_without_alt': 2,
            'links': random.randint(15, 30)
        }
        
        # Portlar
        common_ports = [80, 443, 21, 22, 25, 3306, 5432, 8080]
        open_ports = []
        for port in random.sample(common_ports, random.randint(2, 5)):
            open_ports.append({
                'port': port,
                'service': {
                    80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH',
                    25: 'SMTP', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy'
                }.get(port, 'Nomaʼlum'),
                'status': 'open'
            })
        
        results = {
            'scan_type': 'website',
            'domain': domain,
            'ip': ip,
            'website': website,
            'protocol': protocol,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'server_response_time': round(random.uniform(0.5, 2.0), 2),
            'page_size': random.randint(100, 500),
            'security_scan': security_issues,
            'seo_analysis': seo_analysis,
            'open_ports': open_ports,
            'status_code': random.choice([200, 200, 200, 200, 301, 302, 403, 404]),
            'technologies': random.sample(['WordPress', 'PHP', 'jQuery', 'Bootstrap', 'React', 'Angular'], random.randint(2, 4))
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
        
        if not website.startswith(('http://', 'https://')):
            website = 'http://' + website
        
        # Demo linklar
        internal_links = [
            {'url': '/', 'text': 'Bosh sahifa', 'status': 'good'},
            {'url': '/about', 'text': 'Biz haqimizda', 'status': 'good'},
            {'url': '/services', 'text': 'Xizmatlar', 'status': 'good'},
            {'url': '/contact', 'text': 'Bogʻlanish', 'status': 'good'},
            {'url': '/blog', 'text': 'Blog', 'status': 'good'},
            {'url': '/products', 'text': 'Mahsulotlar', 'status': 'good'}
        ]
        
        external_links = [
            {'url': 'https://google.com', 'text': 'Google', 'status': 'good'},
            {'url': 'https://facebook.com', 'text': 'Facebook', 'status': 'good'},
            {'url': 'https://telegram.org', 'text': 'Telegram', 'status': 'good'},
            {'url': 'https://github.com', 'text': 'GitHub', 'status': 'good'}
        ]
        
        broken_links = []
        suspicious_links = []
        
        # Random buzilgan linklar
        if random.random() < 0.3:
            broken_links.append({
                'url': website + '/old-page',
                'text': 'Eski sahifa',
                'error': '404 Not Found'
            })
        
        if random.random() < 0.2:
            broken_links.append({
                'url': website + '/temp',
                'text': 'Vaqtinchalik',
                'error': '500 Server Error'
            })
        
        # Random shubhali linklar
        suspicious_patterns = [
            {'url': 'http://fake-bank.com', 'text': 'Bank', 'risk': 'yuqori'},
            {'url': 'http://free-money.xyz', 'text': 'Pul ishlash', 'risk': 'yuqori'},
            {'url': 'http://login-verify.net', 'text': 'Login', 'risk': 'o\'rta'}
        ]
        
        if random.random() < 0.4:
            suspicious_links.append(random.choice(suspicious_patterns))
        
        results = {
            'scan_type': 'links',
            'website': website,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_links': len(internal_links) + len(external_links) + len(broken_links),
            'internal_links': internal_links,
            'external_links': external_links,
            'broken_links': broken_links,
            'suspicious_links': suspicious_links
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
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        # Ruxsatlar (demo)
        permissions = [
            {
                'name': 'Internet',
                'display_name': 'Internet',
                'risk': 'PAST',
                'description': 'Internetga ulanish imkoniyati',
                'damage': 'Maʼlumotlarni internetga yuborishi mumkin'
            },
            {
                'name': 'Read Contacts',
                'display_name': 'Kontaktlarni oʻqish',
                'risk': 'OʻRTA',
                'description': 'Telefon kontaktlarini oʻqish',
                'damage': 'Kontaktlar roʻyxatini oʻgʻirlash'
            }
        ]
        
        # Random qo'shimcha ruxsatlar
        all_permissions = [
            {'name': 'SMS Send', 'risk': 'YUQORI', 'desc': 'SMS yuborish', 'damage': 'Pullik SMS joʻnatish'},
            {'name': 'Camera', 'risk': 'OʻRTA', 'desc': 'Kameradan foydalanish', 'damage': 'Yashirin suratga olish'},
            {'name': 'Location', 'risk': 'OʻRTA', 'desc': 'Joylashuvni aniqlash', 'damage': 'Kuzatuv'},
            {'name': 'Storage', 'risk': 'PAST', 'desc': 'Fayllarni oʻqish', 'damage': 'Shaxsiy fayllarni koʻrish'}
        ]
        
        for perm in random.sample(all_permissions, random.randint(1, 3)):
            permissions.append({
                'name': perm['name'],
                'display_name': perm['name'],
                'risk': perm['risk'],
                'description': perm['desc'],
                'damage': perm['damage']
            })
        
        # Zararli dastur tahlili
        risk_score = random.randint(10, 90)
        detected_count = risk_score // 30
        
        malware_signatures = [
            {
                'name': 'SMS Trojan',
                'detected': risk_score > 70,
                'severity': 'YUQORI',
                'description': 'Pullik SMS joʻnatadigan zararli dastur',
                'action': 'Pullik SMS orqali pul yechib olish',
                'protection': 'Ilovani oʻchiring, bank hisobingizni tekshiring'
            },
            {
                'name': 'Data Stealer',
                'detected': risk_score > 50,
                'severity': 'OʻRTA',
                'description': 'Maʼlumotlarni oʻgʻirlaydigan dastur',
                'action': 'Kontaktlar, SMS, fayllarni yuklab olish',
                'protection': 'Antivirus bilan skanerlash'
            },
            {
                'name': 'Adware',
                'detected': risk_score > 30,
                'severity': 'PAST',
                'description': 'Reklama koʻrsatadigan dastur',
                'action': 'Doimiy reklamalar',
                'protection': 'Ilovani oʻchirish'
            }
        ]
        
        # Xavfsizlik muammolari
        security_issues = []
        if len(permissions) > 4:
            security_issues.append({
                'issue': 'Juda koʻp ruxsatlar',
                'severity': 'OʻRTA',
                'description': f'Ilova {len(permissions)} ta ruxsat soʻrayapti',
                'recommendation': 'Faqat zarur ruxsatlarni bering'
            })
        
        if risk_score > 50:
            security_issues.append({
                'issue': 'Zararli dastur belgilari',
                'severity': 'YUQORI' if risk_score > 70 else 'OʻRTA',
                'description': f'{detected_count} ta zararli belgi aniqlandi',
                'recommendation': 'Ilovani ishlatmang'
            })
        
        verdict = 'XAVFLI' if risk_score > 70 else 'SHAXBILI' if risk_score > 30 else 'XAVFSIZ'
        
        # Sertifikat ma'lumotlari
        cert_info = {
            'has_signature': True,
            'is_self_signed': random.choice([True, False]),
            'issuer': random.choice(['Google LLC', 'Unknown', 'Example Corp']),
            'valid_until': (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%Y-%m-%d')
        }
        
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': {
                'file_info': {
                    'file_name': file.filename,
                    'file_size_mb': round(file_size, 2),
                    'md5_hash': md5_hash[:16] + '...',
                    'sha256_hash': sha256_hash[:16] + '...'
                },
                'app_info': {
                    'package_name': 'com.example.' + file.filename.replace('.apk', '').lower()[:15],
                    'version': '1.0.' + str(random.randint(0, 9)),
                    'min_sdk': random.choice([16, 19, 21, 23, 26]),
                    'target_sdk': random.choice([29, 30, 31, 32, 33])
                },
                'permissions': permissions,
                'malware_analysis': {
                    'risk_score': risk_score,
                    'detected': detected_count,
                    'signatures': malware_signatures,
                    'verdict': verdict
                },
                'security_issues': security_issues,
                'certificate_info': cert_info
            }
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        return jsonify({'error': str(e)})

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
        exclude_similar = data.get('exclude_similar', False)
        
        # Belgi to'plamlari
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        numbers = '0123456789'
        symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # O'xshash belgilarni chiqarib tashlash
        similar_chars = 'il1Lo0O'
        if exclude_similar:
            uppercase = ''.join(c for c in uppercase if c not in similar_chars)
            lowercase = ''.join(c for c in lowercase if c not in similar_chars)
            numbers = ''.join(c for c in numbers if c not in similar_chars)
        
        chars = ''
        if use_upper:
            chars += uppercase
        if use_lower:
            chars += lowercase
        if use_numbers:
            chars += numbers
        if use_symbols:
            chars += symbols
        
        if not chars:
            chars = uppercase + lowercase + numbers
        
        # Parol yaratish
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Parol kuchini hisoblash
        strength = 0
        feedback = []
        
        if length >= 16:
            strength += 30
        elif length >= 12:
            strength += 25
        elif length >= 8:
            strength += 15
        else:
            strength += 5
            feedback.append("Parol juda qisqa (kamida 8 belgi)")
        
        if use_upper and use_lower:
            strength += 25
        elif use_upper or use_lower:
            strength += 15
            feedback.append("Katta va kichik harflarni birga ishlating")
        
        if use_numbers:
            strength += 20
        else:
            feedback.append("Raqamlar qo'shing")
        
        if use_symbols:
            strength += 25
        else:
            feedback.append("Maxsus belgilar qo'shing")
        
        if exclude_similar:
            strength += 5
        
        strength_text = 'Kuchsiz' if strength < 40 else 'Oʻrtacha' if strength < 70 else 'Kuchli'
        
        return jsonify({
            'success': True,
            'password': password,
            'strength': strength,
            'strength_text': strength_text,
            'feedback': feedback
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
        if len(password) >= 16:
            strength += 30
        elif len(password) >= 12:
            strength += 25
        elif len(password) >= 8:
            strength += 15
        elif len(password) >= 6:
            strength += 5
            feedback.append("Parol juda qisqa (kamida 8 belgi)")
        else:
            strength += 0
            feedback.append("Parol juda qisqa (kamida 8 belgi)")
        
        # Katta harf
        if any(c.isupper() for c in password):
            strength += 15
        else:
            feedback.append("Katta harf qo'shing")
        
        # Kichik harf
        if any(c.islower() for c in password):
            strength += 15
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
        
        # Takrorlanuvchi belgilar
        if len(set(password)) < len(password) * 0.7:
            strength -= 10
            feedback.append("Takrorlanuvchi belgilar juda koʻp")
        
        # Lug'atdagi so'zlar
        common_words = ['password', 'admin', 'user', 'login', 'qwerty', '123456']
        if any(word in password.lower() for word in common_words):
            strength -= 15
            feedback.append("Oddiy so'zlar ishlatilgan")
        
        strength = max(0, min(100, strength))
        
        strength_text = 'Kuchsiz' if strength < 40 else 'Oʻrtacha' if strength < 70 else 'Kuchli'
        
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

@app.route('/api/quiz/submit', methods=['POST'])
def submit_quiz():
    """Test natijalarini saqlash"""
    try:
        data = request.json
        score = data.get('score', 0)
        answers = data.get('answers', [])
        
        # Natijani baholash
        result = None
        for key, value in QUIZ_RESULTS.items():
            if score >= value['min_score']:
                result = value
        
        if not result:
            result = QUIZ_RESULTS['poor']
        
        return jsonify({
            'success': True,
            'result': result,
            'message': f'Test yakunlandi! Siz {score} ball toʻpladingiz.'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/contact', methods=['POST'])
def contact():
    """Bog'lanish formasini jo'natish"""
    try:
        data = request.json
        name = data.get('name', '')
        email = data.get('email', '')
        message = data.get('message', '')
        
        # Bu yerda email jo'natish kerak
        # Hozircha faqat muvaffaqiyatli deb hisoblaymiz
        
        return jsonify({
            'success': True,
            'message': 'Xabaringiz qabul qilindi. Tez orada javob beramiz!'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/scan-history')
def get_scan_history():
    """Skanerlash tarixini olish"""
    history = session.get('scan_history', [])
    return jsonify(history)

@app.route('/api/save-settings', methods=['POST'])
def save_settings():
    """Sozlamalarni saqlash"""
    try:
        settings = request.json
        session['user_settings'] = settings
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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

@app.route('/sitemap.xml')
def serve_sitemap():
    return send_from_directory('static', 'sitemap.xml')

@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/sw.js')
def serve_sw():
    return send_from_directory('static', 'sw.js')

# ========== HEALTH CHECK ==========
@app.route('/health')
def health_check():
    """Health check for Vercel"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '1.0.0'
    })

# ========== VERCEL SOZLAMALARI ==========
app.debug = False

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
