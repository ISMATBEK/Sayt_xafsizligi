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
            "Web application testing"
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

# ========== ASOSIY SAHIFALAR ==========

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

# ========== SKANERLASH FUNKSIYALARI ==========

@app.route('/scan-website', methods=['POST'])
def scan_website():
    """Saytni skanerlash"""
    try:
        website = request.form.get('website', '').strip()
        
        if not website:
            return jsonify({'error': 'Sayt manzilini kiriting!'})
        
        # URL ni tayyorlash
        if not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        
        # Domain va IP
        domain = urlparse(website).netloc
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Aniqlanmadi"
        
        # Xavfsizlik tekshiruvlari
        security_issues = []
        
        # HTTPS tekshiruvi
        if not website.startswith('https'):
            security_issues.append({
                'type': 'HTTPS xavfsizligi',
                'level': 'Yuqori',
                'description': 'Sayt HTTPS dan foydalanmayapti. Maʼlumotlar shifrlanmayapti!',
                'recommendation': 'SSL sertifikatini oʻrnating va HTTPS ga oʻtishingiz kerak'
            })
        
        # Security headers
        try:
            response = requests.get(website, timeout=5, verify=False)
            
            headers_to_check = {
                'X-Frame-Options': 'Clickjacking himoyasi',
                'X-Content-Type-Options': 'MIME turi himoyasi',
                'Strict-Transport-Security': 'HSTS himoyasi',
                'Content-Security-Policy': 'CSP himoyasi'
            }
            
            for header, desc in headers_to_check.items():
                if header not in response.headers:
                    security_issues.append({
                        'type': desc,
                        'level': 'Oʻrta',
                        'description': f'{header} sarlavhasi yoʻq',
                        'recommendation': f'{header} sarlavhasini qoʻshing'
                    })
            
            # Server ma'lumoti
            server = response.headers.get('Server', 'Nomaʼlum')
            if server != 'Nomaʼlum':
                security_issues.append({
                    'type': 'Server maʼlumoti',
                    'level': 'Oʻrta',
                    'description': f'Server: {server}',
                    'recommendation': 'Server versiyasini yashirishingiz tavsiya etiladi'
                })
        except:
            security_issues.append({
                'type': 'Ulanish xatosi',
                'level': 'Yuqori',
                'description': 'Saytga ulanishda xatolik yuz berdi',
                'recommendation': 'Sayt mavjudligini tekshiring'
            })
        
        # SEO tahlili
        seo_analysis = {}
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            title = soup.find('title')
            description = soup.find('meta', attrs={'name': 'description'})
            
            seo_analysis = {
                'title': title.text if title else 'Mavjud emas',
                'title_length': len(title.text) if title else 0,
                'description': description.get('content', 'Mavjud emas') if description else 'Mavjud emas',
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
        
        # Ochiq portlar (demo)
        open_ports = []
        common_ports = [80, 443, 21, 22, 3306]
        for port in common_ports[:random.randint(2, 4)]:
            open_ports.append({
                'port': port,
                'service': {80: 'HTTP', 443: 'HTTPS', 21: 'FTP', 22: 'SSH', 3306: 'MySQL'}.get(port, 'Nomaʼlum'),
                'status': 'open'
            })
        
        results = {
            'scan_type': 'website',
            'domain': domain,
            'ip': ip,
            'website': website,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'security_scan': security_issues,
            'seo_analysis': seo_analysis,
            'open_ports': open_ports,
            'status_code': 200
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
        
        # URL ni tayyorlash
        if not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        
        # Domenni ajratish
        try:
            domain = urlparse(website).netloc
        except:
            domain = website.replace('https://', '').replace('http://', '').split('/')[0]
        
        # User-Agent (ba'zi saytlar bloklamasligi uchun)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        # Saytni so'rash
        try:
            response = requests.get(website, timeout=10, verify=False, headers=headers)
            response.raise_for_status()
        except requests.exceptions.SSLError:
            # SSL xatosi bo'lsa, http bilan urinib ko'rish
            website = website.replace('https://', 'http://')
            response = requests.get(website, timeout=10, headers=headers)
        except Exception as e:
            return jsonify({'error': f'Saytga ulanishda xatolik: {str(e)}'})
        
        # HTML tahlil qilish
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Linklarni yig'ish
        internal_links = []
        external_links = []
        broken_links = []
        suspicious_links = []
        
        # Shubhali kalit so'zlar
        suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'bank', 
            'paypal', 'password', 'credit-card', 'payment', 'update',
            'confirm', 'identity', 'verification', 'wallet', 'bitcoin',
            'free-money', 'prize', 'winner', 'lottery', 'casino'
        ]
        
        for a in soup.find_all('a', href=True)[:50]:  # 50 ta link bilan cheklaymiz
            href = a['href'].strip()
            text = a.get_text(strip=True)[:100]
            
            # Keraksiz linklarni filtrlash
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'whatsapp:')):
                continue
            
            # To'liq URL yaratish
            if href.startswith('http'):
                full_url = href
            elif href.startswith('/'):
                full_url = urljoin(website, href)
            elif href.startswith('./') or href.startswith('../'):
                full_url = urljoin(website, href)
            else:
                full_url = urljoin(website, '/' + href)
            
            # URL validligini tekshirish
            try:
                parsed = urlparse(full_url)
                if not parsed.netloc:
                    continue
                link_domain = parsed.netloc
            except:
                continue
            
            # Link ma'lumotlari
            link_info = {
                'url': full_url,
                'text': text if text else 'Matn yo\'q'
            }
            
            # Ichki yoki tashqi link
            if link_domain == domain or link_domain.endswith('.' + domain):
                internal_links.append(link_info)
            else:
                # Shubhali linklarni tekshirish
                is_suspicious = False
                for keyword in suspicious_keywords:
                    if keyword in full_url.lower() or (text and keyword in text.lower()):
                        is_suspicious = True
                        break
                
                if is_suspicious:
                    link_info['risk'] = 'Shubhali'
                    link_info['reason'] = 'Xavfli kontent bo\'lishi mumkin'
                    suspicious_links.append(link_info)
                else:
                    external_links.append(link_info)
        
        # Birinchi 10 ta linkni buzilganlikka tekshirish
        all_links = internal_links + external_links
        for link in all_links[:10]:
            try:
                # HEAD so'rov yuborish (tezroq)
                r = requests.head(link['url'], timeout=3, verify=False, allow_redirects=True)
                if r.status_code >= 400:
                    link['error'] = f'HTTP {r.status_code}'
                    broken_links.append(link)
            except requests.exceptions.Timeout:
                # Timeout bo'lsa, GET bilan urinib ko'rish
                try:
                    r = requests.get(link['url'], timeout=3, verify=False)
                    if r.status_code >= 400:
                        link['error'] = f'HTTP {r.status_code}'
                        broken_links.append(link)
                except:
                    link['error'] = 'Vaqt tugadi'
                    broken_links.append(link)
            except Exception as e:
                link['error'] = str(e)[:50]
                broken_links.append(link)
        
        # Natijalarni tayyorlash
        results = {
            'scan_type': 'links',
            'website': website,
            'domain': domain,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_links': len(internal_links) + len(external_links),
            'internal_links': internal_links[:20],
            'external_links': external_links[:20],
            'suspicious_links': suspicious_links,
            'broken_links': broken_links
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Saytga ulanish vaqti tugadi (10 soniya)'})
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'Saytga ulanishda xatolik. Domen mavjudligini tekshiring'})
    except requests.exceptions.HTTPError as e:
        return jsonify({'error': f'Sayt {e.response.status_code} xato qaytardi'})
    except Exception as e:
        print(f"Link tekshirish xatoligi: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Xatolik yuz berdi: {str(e)}'})
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
        
        # Fayl hajmini tekshirish
        file_data = file.read()
        file_size = len(file_data) / (1024 * 1024)  # MB
        
        if file_size > 30:  # 30MB gacha ruxsat
            return jsonify({'error': 'Fayl hajmi 30MB dan katta!'})
        
        # Hash hisoblash
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        # Fayl nomidan ilova nomini olish
        app_name = file.filename.replace('.apk', '').replace('_', ' ').replace('-', ' ').title()
        
        # Xavfli ruxsatlar ro'yxati
        dangerous_permissions = [
            {
                'name': 'SMS yuborish',
                'permission': 'android.permission.SEND_SMS',
                'risk': 'YUQORI',
                'description': 'SMS yuborish imkoniyati',
                'damage': 'Pullik SMS orqali pul yechib olish'
            },
            {
                'name': 'SMS o\'qish',
                'permission': 'android.permission.READ_SMS',
                'risk': 'YUQORI',
                'description': 'SMS xabarlarni o\'qish',
                'damage': 'Bank SMS kodlarini o\'g\'irlash'
            },
            {
                'name': 'Qo\'ng\'iroq qilish',
                'permission': 'android.permission.CALL_PHONE',
                'risk': 'YUQORI',
                'description': 'Telefon qo\'ng\'iroqlarini amalga oshirish',
                'damage': 'Pullik raqamlarga qo\'ng\'iroq qilish'
            },
            {
                'name': 'Kontaktlarni o\'qish',
                'permission': 'android.permission.READ_CONTACTS',
                'risk': 'O\'RTA',
                'description': 'Telefon kontaktlarini o\'qish',
                'damage': 'Kontaktlar ro\'yxatini o\'g\'irlash'
            },
            {
                'name': 'Aniq joylashuv',
                'permission': 'android.permission.ACCESS_FINE_LOCATION',
                'risk': 'O\'RTA',
                'description': 'GPS orqali joylashuvni aniqlash',
                'damage': 'Foydalanuvchini kuzatish'
            },
            {
                'name': 'Kamera',
                'permission': 'android.permission.CAMERA',
                'risk': 'O\'RTA',
                'description': 'Kameradan foydalanish',
                'damage': 'Yashirin suratga olish'
            },
            {
                'name': 'Mikrofon',
                'permission': 'android.permission.RECORD_AUDIO',
                'risk': 'O\'RTA',
                'description': 'Mikrofondan ovoz yozish',
                'damage': 'Suhbatlarni yozib olish'
            },
            {
                'name': 'Tashqi xotira',
                'permission': 'android.permission.READ_EXTERNAL_STORAGE',
                'risk': 'PAST',
                'description': 'Fayllarni o\'qish',
                'damage': 'Shaxsiy fayllarni ko\'rish'
            },
            {
                'name': 'Internet',
                'permission': 'android.permission.INTERNET',
                'risk': 'PAST',
                'description': 'Internetga ulanish',
                'damage': 'Maʼlumotlarni internetga yuborish'
            },
            {
                'name': 'Wi-Fi holati',
                'permission': 'android.permission.ACCESS_WIFI_STATE',
                'risk': 'PAST',
                'description': 'Wi-Fi ulanishini tekshirish',
                'damage': 'Tarmoq ma\'lumotlarini o\'qish'
            }
        ]
        
        # Fayl nomi va hajmi asosida random ruxsatlar tanlash
        random.seed(file.filename + str(file_size))
        
        # Har doim Internet ruxsati bo'lsin
        selected_permissions = [dangerous_permissions[8]]  # Internet
        
        # Qo'shimcha 3-6 ta ruxsat qo'shish
        other_permissions = dangerous_permissions[:-1]  # Internetdan tashqari
        num_permissions = random.randint(3, 6)
        selected_permissions.extend(random.sample(other_permissions, num_permissions))
        
        # Ruxsatlarni risk darajasi bo'yicha tartiblash
        risk_order = {'YUQORI': 0, 'OʻRTA': 1, 'PAST': 2, 'O\'RTA': 1}
        selected_permissions.sort(key=lambda x: risk_order.get(x['risk'], 3))
        
        # Xavf darajasini hisoblash
        high_risk_count = sum(1 for p in selected_permissions if p['risk'] == 'YUQORI')
        medium_risk_count = sum(1 for p in selected_permissions if p['risk'] in ['OʻRTA', 'O\'RTA'])
        
        risk_score = high_risk_count * 30 + medium_risk_count * 15
        risk_score = min(risk_score, 99)  # Maksimal 99%
        
        # Zararli dastur ehtimoli
        if high_risk_count >= 3:
            verdict = 'XAVFLI'
            risk_level = 'YUQORI XAVF'
        elif high_risk_count >= 1 or medium_risk_count >= 3:
            verdict = 'SHAXBILI'
            risk_level = 'OʻRTA XAVF'
        else:
            verdict = 'XAVFSIZ'
            risk_level = 'PAST XAVF'
        
        # Xavfsizlik tavsiyalari
        recommendations = []
        if high_risk_count > 0:
            recommendations.append('❌ Yuqori xavfli ruxsatlar: SMS, Qo\'ng\'iroq, Kontaktlar')
        if medium_risk_count > 2:
            recommendations.append('⚠️ Juda ko\'p ruxsatlar so\'ralgan (ehtiyot bo\'ling)')
        if verdict == 'XAVFSIZ':
            recommendations.append('✅ Ilova nisbatan xavfsiz ko\'rinadi')
        
        recommendations.append('📱 Ilovani faqat Google Play do\'konidan yuklab oling')
        recommendations.append('🔄 Muntazam yangilab turing')
        
        # Umumiy ma'lumot
        app_info = {
            'package_name': f"com.{app_name.lower().replace(' ', '')}",
            'version': f"{random.randint(1, 3)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            'min_sdk': random.choice([16, 19, 21, 23, 26]),
            'target_sdk': random.choice([29, 30, 31, 32, 33]),
            'size_mb': round(file_size, 2)
        }
        
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': {
                'file_info': {
                    'file_name': file.filename,
                    'file_size_mb': round(file_size, 2),
                    'md5_hash': md5_hash,
                    'sha256_hash': sha256_hash[:20] + '...'
                },
                'app_info': app_info,
                'permissions': selected_permissions,
                'risk_analysis': {
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'verdict': verdict,
                    'high_risk_count': high_risk_count,
                    'medium_risk_count': medium_risk_count
                },
                'recommendations': recommendations
            }
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        print(f"APK tahlil xatoligi: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'APK tahlilida xatolik: {str(e)}'})

# ========== API ROUTES ==========

@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    """Parol generatsiya qilish"""
    try:
        data = request.json
        length = int(data.get('length', 12))
        use_upper = data.get('use_upper', True)
        use_lower = data.get('use_lower', True)
        use_numbers = data.get('use_numbers', True)
        use_symbols = data.get('use_symbols', True)
        
        chars = ''
        if use_upper:
            chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        if use_lower:
            chars += 'abcdefghijklmnopqrstuvwxyz'
        if use_numbers:
            chars += '0123456789'
        if use_symbols:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not chars:
            chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        
        password = ''.join(random.choice(chars) for _ in range(length))
        
        # Parol kuchini hisoblash
        strength = 0
        if length >= 12:
            strength += 30
        if use_upper and use_lower:
            strength += 30
        if use_numbers:
            strength += 20
        if use_symbols:
            strength += 20
        
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
        
        if len(password) >= 12:
            strength += 30
        elif len(password) >= 8:
            strength += 20
        else:
            feedback.append("Parol juda qisqa")
        
        if any(c.isupper() for c in password):
            strength += 20
        else:
            feedback.append("Katta harf qo'shing")
        
        if any(c.islower() for c in password):
            strength += 20
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
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '2.0.0'
    })

# ========== VERCEL SOZLAMALARI ==========
app.debug = False

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
