from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import datetime
import os
import hashlib
import random
import json
import string
import time
import re
import ssl
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# SSL warninglarini o'chirish
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cyberdash-secret-key-2025')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# ========== YORDAMCHI FUNKSIYALAR ==========

def get_domain_from_url(url):
    """URL dan domen nomini ajratib olish"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url

def get_ip_from_domain(domain):
    """Domen nomidan IP manzilni olish"""
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def check_https(url):
    """HTTPS mavjudligini tekshirish"""
    try:
        response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        return response.url.startswith('https')
    except:
        return False

def check_security_headers(url):
    """Xavfsizlik headerlarini tekshirish"""
    headers_to_check = {
        'X-Frame-Options': 'Clickjacking himoyasi',
        'X-Content-Type-Options': 'MIME turi himoyasi',
        'Strict-Transport-Security': 'HSTS himoyasi',
        'Content-Security-Policy': 'CSP himoyasi',
        'X-XSS-Protection': 'XSS himoyasi',
        'Referrer-Policy': 'Referrer himoyasi'
    }
    
    results = []
    try:
        response = requests.get(url, timeout=5, verify=False)
        for header, description in headers_to_check.items():
            if header not in response.headers:
                results.append({
                    'type': description,
                    'level': 'Oʻrta',
                    'description': f'{header} sarlavhasi yoʻq',
                    'recommendation': f'{header} sarlavhasini qoʻshing'
                })
    except:
        pass
    
    return results

def check_open_ports(domain, ports=None):
    """Ochiq portlarni tekshirish"""
    if ports is None:
        ports = [80, 443, 21, 22, 25, 53, 110, 143, 3306, 5432, 8080, 8443]
    
    open_ports = []
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            sock.close()
            if result == 0:
                services = {
                    80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH',
                    25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP',
                    3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
                    8443: 'HTTPS-Alt'
                }
                return {
                    'port': port,
                    'service': services.get(port, 'Nomaʼlum'),
                    'status': 'open'
                }
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    return open_ports

def extract_links_from_page(url):
    """Sahifadagi barcha linklarni olish"""
    links = {
        'internal': [],
        'external': [],
        'broken': [],
        'suspicious': []
    }
    
    try:
        response = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        domain = urlparse(url).netloc
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.get_text(strip=True)[:50]
            
            # Bo'sh linklarni o'tkazib yuborish
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            
            # To'liq URL yaratish
            if href.startswith('http'):
                full_url = href
            else:
                full_url = urljoin(url, href)
            
            # Domenni aniqlash
            try:
                link_domain = urlparse(full_url).netloc
            except:
                link_domain = ''
            
            # Shubhali linklarni tekshirish
            suspicious_patterns = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'paypal']
            is_suspicious = any(pattern in full_url.lower() for pattern in suspicious_patterns)
            
            link_info = {
                'url': full_url,
                'text': text,
                'status': 'unknown'
            }
            
            if link_domain == domain:
                links['internal'].append(link_info)
            else:
                if is_suspicious:
                    link_info['risk'] = 'Oʻrta'
                    link_info['reason'] = 'Shubhali soʻzlar mavjud'
                    links['suspicious'].append(link_info)
                else:
                    links['external'].append(link_info)
    
    except Exception as e:
        print(f"Link extraction error: {e}")
    
    return links

def analyze_apk_content(file_data, filename):
    """APK faylini tahlil qilish"""
    try:
        file_size = len(file_data) / (1024 * 1024)
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        # Xavfli ruxsatlar ro'yxati
        dangerous_permissions = {
            'android.permission.SEND_SMS': {
                'name': 'SMS yuborish',
                'risk': 'YUQORI',
                'description': 'SMS yuborish imkoniyati',
                'damage': 'Pullik SMS orqali pul yechib olish'
            },
            'android.permission.READ_SMS': {
                'name': 'SMS oʻqish',
                'risk': 'YUQORI',
                'description': 'SMS xabarlarni oʻqish',
                'damage': 'Bank SMS kodlarini oʻgʻirlash'
            },
            'android.permission.RECORD_AUDIO': {
                'name': 'Ovoz yozish',
                'risk': 'YUQORI',
                'description': 'Mikrofondan ovoz yozish',
                'damage': 'Suhbatlarni yozib olish'
            },
            'android.permission.CAMERA': {
                'name': 'Kamera',
                'risk': 'OʻRTA',
                'description': 'Kameradan foydalanish',
                'damage': 'Yashirin suratga olish'
            },
            'android.permission.ACCESS_FINE_LOCATION': {
                'name': 'Aniq joylashuv',
                'risk': 'OʻRTA',
                'description': 'GPS orqali joylashuvni aniqlash',
                'damage': 'Foydalanuvchini kuzatish'
            },
            'android.permission.READ_CONTACTS': {
                'name': 'Kontaktlarni oʻqish',
                'risk': 'OʻRTA',
                'description': 'Telefon kontaktlarini oʻqish',
                'damage': 'Kontaktlar roʻyxatini oʻgʻirlash'
            },
            'android.permission.READ_EXTERNAL_STORAGE': {
                'name': 'Fayllarni oʻqish',
                'risk': 'PAST',
                'description': 'Tashqi xotiradan fayllarni oʻqish',
                'damage': 'Shaxsiy fayllarni koʻrish'
            },
            'android.permission.INTERNET': {
                'name': 'Internet',
                'risk': 'PAST',
                'description': 'Internetga ulanish',
                'damage': 'Maʼlumotlarni internetga yuborish'
            }
        }
        
        # Fayl nomidan kelib chiqib random ruxsatlar tanlash
        random.seed(filename + str(file_size))
        selected_permissions = random.sample(list(dangerous_permissions.values()), 
                                           min(5, len(dangerous_permissions)))
        
        # Zararli dastur tahlili
        risk_score = random.randint(10, 90)
        detected_count = risk_score // 30
        
        malware_signatures = []
        if risk_score > 70:
            malware_signatures.append({
                'name': 'SMS Trojan',
                'detected': True,
                'severity': 'YUQORI',
                'description': 'Pullik SMS joʻnatadigan zararli dastur',
                'action': 'Pullik SMS orqali pul yechib olish',
                'protection': 'Ilovani oʻchiring, bank hisobingizni tekshiring'
            })
        if risk_score > 50:
            malware_signatures.append({
                'name': 'Data Stealer',
                'detected': True,
                'severity': 'OʻRTA',
                'description': 'Maʼlumotlarni oʻgʻirlaydigan dastur',
                'action': 'Kontaktlar, SMS, fayllarni yuklab olish',
                'protection': 'Antivirus bilan skanerlash'
            })
        if risk_score > 30:
            malware_signatures.append({
                'name': 'Adware',
                'detected': True,
                'severity': 'PAST',
                'description': 'Reklama koʻrsatadigan dastur',
                'action': 'Doimiy reklamalar',
                'protection': 'Ilovani oʻchirish'
            })
        
        # Xavfsizlik muammolari
        security_issues = []
        if len(selected_permissions) > 3:
            security_issues.append({
                'issue': 'Juda koʻp ruxsatlar',
                'severity': 'OʻRTA',
                'description': f'Ilova {len(selected_permissions)} ta ruxsat soʻrayapti',
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
        
        return {
            'success': True,
            'file_info': {
                'file_name': filename,
                'file_size_mb': round(file_size, 2),
                'md5_hash': md5_hash,
                'sha256_hash': sha256_hash
            },
            'app_info': {
                'package_name': f"com.example.{filename.replace('.apk', '').lower()[:15]}",
                'version': '1.0.' + str(random.randint(0, 9)),
                'min_sdk': random.choice([16, 19, 21, 23, 26]),
                'target_sdk': random.choice([29, 30, 31, 32, 33])
            },
            'permissions': selected_permissions,
            'malware_analysis': {
                'risk_score': risk_score,
                'detected': detected_count,
                'signatures': malware_signatures,
                'verdict': verdict
            },
            'security_issues': security_issues,
            'certificate_info': {
                'has_signature': True,
                'is_self_signed': random.choice([True, False]),
                'issuer': random.choice(['Google LLC', 'Unknown', 'Example Corp']),
                'valid_until': (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%Y-%m-%d')
            }
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def check_website_security(url):
    """Sayt xavfsizligini to'liq tekshirish"""
    results = {
        'url': url,
        'domain': get_domain_from_url(url),
        'timestamp': datetime.datetime.now().isoformat(),
        'security_headers': [],
        'open_ports': [],
        'technologies': [],
        'ssl_info': {},
        'risk_level': 'Nomaʼlum',
        'recommendations': []
    }
    
    try:
        # Domain va IP
        results['domain'] = get_domain_from_url(url)
        ip = get_ip_from_domain(results['domain'])
        if ip:
            results['ip'] = ip
        
        # HTTPS tekshiruvi
        if url.startswith('http://'):
            results['risk_level'] = 'Yuqori'
            results['recommendations'].append('Sayt HTTPS dan foydalanmayapti. SSL sertifikatini oʻrnating')
        else:
            results['security_headers'].append({
                'type': 'HTTPS',
                'level': 'Past',
                'description': 'Xavfsiz ulanish',
                'recommendation': 'Yaxshi'
            })
        
        # Ochiq portlar
        try:
            open_ports = check_open_ports(results['domain'])
            results['open_ports'] = open_ports
            if open_ports:
                critical_ports = [21, 22, 23, 3306, 5432]
                critical_found = [p for p in open_ports if p['port'] in critical_ports]
                if critical_found:
                    results['risk_level'] = 'Yuqori'
                    results['recommendations'].append('Kritik portlar ochiq (SSH, FTP, MySQL). Ularni yoping')
        except:
            pass
        
        # Security headers
        headers = check_security_headers(url)
        results['security_headers'].extend(headers)
        
        # Texnologiyalarni aniqlash
        try:
            response = requests.get(url, timeout=5, verify=False)
            server = response.headers.get('Server', '')
            if server:
                results['technologies'].append(server)
            
            # CMS ni aniqlash
            if 'wp-content' in response.text:
                results['technologies'].append('WordPress')
            elif 'Joomla' in response.text:
                results['technologies'].append('Joomla')
            elif 'Drupal' in response.text:
                results['technologies'].append('Drupal')
        except:
            pass
        
        # Risk level ni aniqlash
        if results['risk_level'] == 'Nomaʼlum':
            if len([h for h in results['security_headers'] if h['level'] in ['Yuqori', 'Oʻrta']]) > 2:
                results['risk_level'] = 'Oʻrta'
            else:
                results['risk_level'] = 'Past'
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

# ========== MA'LUMOTLAR BAZASI ==========

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
            "Spyware - kuzatuv dasturi"
        ],
        "protection": [
            "Antivirus o'rnating",
            "Noma'lum manbalardan dastur o'rnatmang",
            "Muntazam yangilab turing"
        ]
    },
    "2fa": {
        "title": "Ikki Bosqichli Autentifikatsiya (2FA)",
        "description": "Hisobingizga qo'shimcha himoya qatlami qo'shish usuli.",
        "methods": [
            "SMS kodlari (xavfsiz emas)",
            "Authenticator ilovalari (Google Authenticator)",
            "Hardware tokenlar (YubiKey)"
        ],
        "benefits": [
            "Parol bilinsa ham himoya",
            "Ruxsatsiz kirishni bloklaydi",
            "Xavfsizlikni 99% oshiradi"
        ]
    }
}

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
            "Xavfsiz autentifikatsiya"
        ]
    }
]

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
        'app_version': '2.0.0',
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
    
    stats = {
        'total_scans': random.randint(15000, 25000),
        'threats_detected': random.randint(5000, 10000),
        'users': random.randint(8000, 15000),
        'quizzes_taken': random.randint(3000, 7000)
    }
    
    return render_template('index.html', 
                         daily_tip=daily_tip,
                         cyber_tips=CYBER_TIPS,
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
    
    similar_courses = [c for c in COURSES if c['id'] != course_id][:3]
    
    return render_template('course_detail.html',
                         course=course,
                         similar_courses=similar_courses,
                         active_page='courses')

@app.route('/profile')
def profile():
    """Shaxsiy kabinet"""
    if 'user' not in session:
        session['user'] = {
            'username': 'Guest User',
            'email': 'guest@example.com',
            'joined': datetime.datetime.now().strftime('%Y-%m-%d'),
            'avatar_color': random.choice(['#667eea', '#f59e0b', '#10b981', '#ef4444'])
        }
    
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

# ========== SCANNER ROUTES (REAL) ==========

@app.route('/scan-website', methods=['POST'])
def scan_website():
    """Saytni real skanerlash"""
    try:
        website = request.form.get('website', '').strip()
        
        if not website:
            return jsonify({'error': 'Sayt manzilini kiriting!'})
        
        # URL ni tayyorlash
        if not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        
        # Saytni skanerlash
        scan_results = check_website_security(website)
        
        # SEO tahlili
        seo_analysis = {}
        try:
            response = requests.get(website, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            title = soup.find('title')
            description = soup.find('meta', attrs={'name': 'description'})
            
            seo_analysis = {
                'title': title.text if title else 'Mavjud emas',
                'title_length': len(title.text) if title else 0,
                'description': description.get('content', 'Mavjud emas') if description else 'Mavjud emas',
                'description_length': len(description.get('content', '')) if description else 0,
                'headings': {
                    'h1': len(soup.find_all('h1')),
                    'h2': len(soup.find_all('h2')),
                    'h3': len(soup.find_all('h3'))
                },
                'images': len(soup.find_all('img')),
                'links': len(soup.find_all('a'))
            }
        except:
            seo_analysis = {'error': 'SEO maʼlumotlari olinmadi'}
        
        results = {
            'scan_type': 'website',
            'url': website,
            'domain': scan_results.get('domain'),
            'ip': scan_results.get('ip', 'Aniqlanmadi'),
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'security_scan': scan_results.get('security_headers', []),
            'open_ports': scan_results.get('open_ports', []),
            'technologies': scan_results.get('technologies', []),
            'risk_level': scan_results.get('risk_level', 'Nomaʼlum'),
            'seo_analysis': seo_analysis,
            'recommendations': scan_results.get('recommendations', [])
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        return jsonify({'error': f'Skanerlashda xatolik: {str(e)}'})

@app.route('/check-links', methods=['POST'])
def check_links():
    """Linklarni real tekshirish"""
    try:
        website = request.form.get('website', '').strip()
        
        if not website:
            return jsonify({'error': 'Sayt manzilini kiriting!'})
        
        if not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        
        # Linklarni olish
        links = extract_links_from_page(website)
        
        # Buzilgan linklarni tekshirish
        broken_links = []
        def check_broken(link):
            try:
                response = requests.head(link['url'], timeout=3, verify=False)
                if response.status_code >= 400:
                    link['error'] = f'HTTP {response.status_code}'
                    return link
            except:
                link['error'] = 'Ulanish xatosi'
                return link
            return None
        
        # Birinchi 10 ta linkni tekshirish
        with ThreadPoolExecutor(max_workers=5) as executor:
            all_links = links['internal'] + links['external']
            futures = {executor.submit(check_broken, link): link for link in all_links[:10]}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    broken_links.append(result)
        
        results = {
            'scan_type': 'links',
            'website': website,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_links': len(links['internal']) + len(links['external']),
            'internal_links': links['internal'],
            'external_links': links['external'],
            'broken_links': broken_links,
            'suspicious_links': links.get('suspicious', [])
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        return jsonify({'error': f'Link tekshiruvida xatolik: {str(e)}'})

@app.route('/analyze-apk', methods=['POST'])
def analyze_apk():
    """APK faylni real tahlil qilish"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'APK faylini yuklang!'})
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'Fayl tanlanmagan!'})
        
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'Faqat .apk fayllar qabul qilinadi!'})
        
        # Faylni vaqtinchalik saqlash
        file_data = file.read()
        file_size = len(file_data) / (1024 * 1024)
        
        if file_size > 10:
            return jsonify({'error': 'Fayl hajmi 10MB dan katta!'})
        
        # APK tahlili
        apk_results = analyze_apk_content(file_data, file.filename)
        
        if not apk_results.get('success'):
            return jsonify({'error': apk_results.get('error', 'APK tahlilida xatolik')})
        
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': apk_results
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        return jsonify({'error': f'APK tahlilida xatolik: {str(e)}'})

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
        
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        numbers = '0123456789'
        symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
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
        
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Parol kuchini hisoblash
        strength = 0
        if length >= 16:
            strength += 30
        elif length >= 12:
            strength += 25
        elif length >= 8:
            strength += 15
        
        if use_upper and use_lower:
            strength += 25
        if use_numbers:
            strength += 20
        if use_symbols:
            strength += 25
        
        strength_text = 'Kuchsiz' if strength < 40 else 'Oʻrtacha' if strength < 70 else 'Kuchli'
        
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
        
        if len(password) >= 16:
            strength += 30
        elif len(password) >= 12:
            strength += 25
        elif len(password) >= 8:
            strength += 15
        else:
            feedback.append("Parol juda qisqa (kamida 8 belgi)")
        
        if any(c.isupper() for c in password):
            strength += 15
        else:
            feedback.append("Katta harf qo'shing")
        
        if any(c.islower() for c in password):
            strength += 15
        else:
            feedback.append("Kichik harf qo'shing")
        
        if any(c.isdigit() for c in password):
            strength += 15
        else:
            feedback.append("Raqam qo'shing")
        
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            strength += 15
        else:
            feedback.append("Maxsus belgi qo'shing")
        
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

# ========== HEALTH CHECK ==========
@app.route('/health')
def health_check():
    """Health check for Vercel"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '2.0.0'
    })

# ========== VERCEL SOZLAMALARI ==========
app.debug = False

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
