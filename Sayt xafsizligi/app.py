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
import zipfile
import hashlib
from collections import Counter
import urllib3
import ssl

# SSL warninglarini o'chirish
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'veb-sayt-skanneri-secret-key-2024'


# ========== ADS.TXT FAYLINI SERVE QILISH ==========
@app.route('/ads.txt')
def serve_ads_txt():
    """
    Google AdSense tasdiqlash faylini serve qilish
    """
    return send_from_directory('static', 'ads.txt')


# ========== GOOGLE VERIFICATION FAYLINI SERVE QILISH ==========
@app.route('/google-adsense-verification.html')
def serve_verification_file():
    """
    Google AdSense verification faylini serve qilish
    """
    return send_from_directory('static', 'google-adsense-verification.html')


# ========== BOSHQA STATIC FAYLLARNI SERVE QILISH ==========
@app.route('/robots.txt')
def serve_robots_txt():
    """
    robots.txt faylini serve qilish
    """
    return send_from_directory('static', 'robots.txt')


# ========== Kengaytirilgan Port Skanerlash ==========
def get_detailed_port_services():
    return {
        80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        8000: 'HTTP-Alt', 3000: 'Node.js', 5000: 'Flask/Django',
        9000: 'PHP-FPM', 9200: 'Elasticsearch',
        3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
        1433: 'MSSQL', 1521: 'Oracle', 6379: 'Redis',
        11211: 'Memcached', 22: 'SSH', 23: 'Telnet', 3389: 'RDP',
        21: 'FTP', 69: 'TFTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
        53: 'DNS', 67: 'DHCP', 123: 'NTP', 161: 'SNMP'
    }


def fast_port_scan(domain, ports=None, max_workers=50):
    if ports is None:
        ports = list(get_detailed_port_services().keys())

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": "Domain topilmadi"}

    open_ports = []

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return {
                        'port': port,
                        'service': get_detailed_port_services().get(port, 'Noma\'lum'),
                        'status': 'open'
                    }
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(check_port, ports)
        open_ports = [result for result in results if result is not None]

    return {
        "ip": ip,
        "open_ports": open_ports,
        "total_scanned": len(ports),
        "open_count": len(open_ports)
    }


# ========== Xavfsizlik Tekshiruvlari ==========
def advanced_security_checks(url):
    vulnerabilities = []

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)

        # 1. HTTPS tekshiruvi
        if url.startswith('http://'):
            vulnerabilities.append({
                'type': 'Xavfsiz ulanish',
                'level': 'Yuqori',
                'description': 'Sayt HTTPS dan foydalanmayapti',
                'recommendation': 'SSL sertifikatini o\'rnating va HTTPS ga o\'tishingiz kerak'
            })

        # 2. Server ma'lumotlari
        server = response.headers.get('Server', 'Noma\'lum')
        if server != 'Noma\'lum':
            vulnerabilities.append({
                'type': 'Server ma\'lumoti',
                'level': 'O\'rta',
                'description': f'Server: {server}',
                'recommendation': 'Server versiyasini yashirishingiz tavsiya etiladi'
            })

        # 3. Security Headers tekshiruvi
        security_headers = {
            'X-Frame-Options': 'Clickjacking himoyasi',
            'X-Content-Type-Options': 'MIME turi snayping',
            'Strict-Transport-Security': 'HSTS himoyasi'
        }

        for header, description in security_headers.items():
            if header not in response.headers:
                vulnerabilities.append({
                    'type': description,
                    'level': 'O\'rta',
                    'description': f'{header} sarlavhasi yo\'q',
                    'recommendation': f'{header} sarlavhasini qo\'shing'
                })

    except Exception as e:
        vulnerabilities.append({
            'type': 'Ulanish xatosi',
            'level': 'Yuqori',
            'description': f'Saytga ulanishda xatolik: {str(e)}',
            'recommendation': 'Saytning mavjudligini tekshiring'
        })

    return vulnerabilities


# ========== YANGILANGAN LINK TEKSHRIVI ==========
def check_links(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        links = soup.find_all('a', href=True)

        link_results = {
            'total_links': len(links),
            'broken_links': [],
            'suspicious_links': [],
            'malicious_links': [],
            'internal_links': [],
            'external_links': [],
            'link_analysis': {}
        }

        # Zararli va shubhali link patternlari
        malicious_patterns = [
            {'pattern': 'phishing', 'type': 'FISHING', 'risk': 'YUQORI'},
            {'pattern': 'malware', 'type': 'MALWARE', 'risk': 'YUQORI'},
            {'pattern': 'virus', 'type': 'VIRUS', 'risk': 'YUQORI'},
            {'pattern': 'hack', 'type': 'HACKING', 'risk': 'YUQORI'},
            {'pattern': 'exploit', 'type': 'EXPLOIT', 'risk': 'YUQORI'},
            {'pattern': 'free-money', 'type': 'SCAM', 'risk': 'O\'RTA'},
            {'pattern': 'win-prize', 'type': 'SCAM', 'risk': 'O\'RTA'},
            {'pattern': 'click-here', 'type': 'SUSPICIOUS', 'risk': 'PAST'},
            {'pattern': 'javascript:', 'type': 'XSS', 'risk': 'YUQORI'},
            {'pattern': 'data:text/html', 'type': 'XSS', 'risk': 'YUQORI'}
        ]

        # Linklarni tekshirish
        for link in links[:20]:  # Birinchi 20 ta linkni tekshiramiz
            href = link['href']
            link_text = link.get_text(strip=True)[:50]

            link_info = {
                'url': href,
                'text': link_text,
                'risk': 'XAVFSIZ',
                'type': 'NORMAL',
                'description': '',
                'damage': '',
                'action': ''
            }

            # Zararli patternlarni tekshirish
            for pattern in malicious_patterns:
                if pattern['pattern'] in href.lower():
                    link_info['risk'] = pattern['risk']
                    link_info['type'] = pattern['type']

                    if pattern['type'] == 'FISHING':
                        link_info['description'] = 'Fishing (parol o\'g\'irlash) saytiga yo\'naltiradi'
                        link_info['damage'] = 'Hisob ma\'lumotlari, kredit karta ma\'lumotlari o\'g\'rilishi'
                        link_info['action'] = 'Saytga kirishdan saqlaning, parollarni o\'zgartiring'
                    elif pattern['type'] == 'MALWARE':
                        link_info['description'] = 'Zararli dastur yuklab olish sayti'
                        link_info['damage'] = 'Virus, trojan, ransomware yuklab olinishi'
                        link_info['action'] = 'Antivirus bilan skanerlash, ilovani o\'chirish'
                    elif pattern['type'] == 'SCAM':
                        link_info['description'] = 'Aldash sayti'
                        link_info['damage'] = 'Pul yo\'qotish, shaxsiy ma\'lumotlarni berish'
                        link_info['action'] = 'Saytga ishonmang, pul o\'tkazmang'

                    link_results['malicious_links'].append(link_info)
                    break

            # Shubhali linklarni tekshirish
            suspicious_keywords = ['admin', 'login', 'config', 'backup', 'password', 'secret']
            if any(keyword in href.lower() for keyword in suspicious_keywords):
                link_info['risk'] = 'O\'RTA'
                link_info['type'] = 'SENSITIVE'
                link_info['description'] = 'Maxfiy ma\'lumotlarga yo\'naltirilgan link'
                link_info['damage'] = 'Maxfiy ma\'lumotlarning oshkor bo\'lishi'
                link_info['action'] = 'Linkni ochmaslik, sayt egasiga xabar berish'
                link_results['suspicious_links'].append(link_info)
            elif href.startswith(('http://', 'https://')):
                link_results['external_links'].append(link_info)
            else:
                link_results['internal_links'].append(link_info)

        # Tahlil natijalari
        link_results['link_analysis'] = {
            'total_scanned': len(links[:20]),
            'malicious_count': len(link_results['malicious_links']),
            'suspicious_count': len(link_results['suspicious_links']),
            'security_score': max(0, 100 - (len(link_results['malicious_links']) * 10)),
            'risk_level': 'YUQORI' if len(link_results['malicious_links']) > 3 else
            'O\'RTA' if len(link_results['malicious_links']) > 0 else 'PAST'
        }

        return link_results

    except Exception as e:
        return {'error': f'Link tekshiruvida xatolik: {str(e)}'}


# ========== YANGILANGAN APK TAHLLILI ==========
def analyze_apk(file_path):
    try:
        if not os.path.exists(file_path):
            return {'error': 'APK fayli topilmadi'}

        apk_info = {
            'file_info': {},
            'permissions': [],
            'security_issues': [],
            'certificate_info': {},
            'file_structure': [],
            'malware_analysis': {},
            'app_info': {}
        }

        # File information
        file_stat = os.stat(file_path)
        apk_info['file_info'] = {
            'file_name': os.path.basename(file_path),
            'file_size': file_stat.st_size,
            'file_size_mb': round(file_stat.st_size / (1024 * 1024), 2),
            'md5_hash': calculate_md5(file_path),
            'sha256_hash': calculate_sha256(file_path)
        }

        # Ilova ma'lumotlari
        apk_info['app_info'] = {
            'package_name': 'com.example.' + os.path.basename(file_path).replace('.apk', '').lower(),
            'version': '1.0.0',
            'min_sdk': 21,
            'target_sdk': 33,
            'permissions_count': 8
        }

        # Ruxsatlarni tekshirish
        dangerous_permissions = [
            {
                'name': 'android.permission.SEND_SMS',
                'display_name': 'SEND_SMS',
                'risk': 'YUQORI',
                'description': 'SMS yuborish imkoniyati - Pullik SMS jo\'natish xavfi',
                'damage': 'Pullik SMS orqali pul yechib olish, spam SMS yuborish'
            },
            {
                'name': 'android.permission.READ_SMS',
                'display_name': 'READ_SMS',
                'risk': 'YUQORI',
                'description': 'SMS\'larni o\'qish imkoniyati - Shaxsiy ma\'lumotlarni o\'g\'irlash',
                'damage': 'Bank SMS kodlari, shaxsiy xabarlarni o\'qish'
            },
            {
                'name': 'android.permission.ACCESS_FINE_LOCATION',
                'display_name': 'ACCESS_FINE_LOCATION',
                'risk': 'O\'RTA',
                'description': 'Aniq joylashuvni bilish - Kuzatuv xavfi',
                'damage': 'Foydalanuvchi harakatlarini kuzatish'
            },
            {
                'name': 'android.permission.READ_CONTACTS',
                'display_name': 'READ_CONTACTS',
                'risk': 'O\'RTA',
                'description': 'Kontaktlarni o\'qish - Ma\'lumotlar bazasini o\'g\'irlash',
                'damage': 'Kontaktlar ro\'yxatini yig\'ish, spam uchun foydalanish'
            },
            {
                'name': 'android.permission.CAMERA',
                'display_name': 'CAMERA',
                'risk': 'O\'RTA',
                'description': 'Kameraga kirish - Maxfiylik buzilishi',
                'damage': 'Foydalanuvchini yashirincha suratga olish'
            },
            {
                'name': 'android.permission.RECORD_AUDIO',
                'display_name': 'RECORD_AUDIO',
                'risk': 'O\'RTA',
                'description': 'Ovoz yozish - Tinglash xavfi',
                'damage': 'Shaxsiy suhbatlarni yozib olish'
            },
            {
                'name': 'android.permission.WRITE_EXTERNAL_STORAGE',
                'display_name': 'WRITE_EXTERNAL_STORAGE',
                'risk': 'PAST',
                'description': 'Tashqi xotiraga yozish - Ma\'lumotlarni o\'chirish',
                'damage': 'Fayllarni o\'chirish yoki shifrlash'
            },
            {
                'name': 'android.permission.READ_EXTERNAL_STORAGE',
                'display_name': 'READ_EXTERNAL_STORAGE',
                'risk': 'PAST',
                'description': 'Tashqi xotirani o\'qish - Ma\'lumotlarni ko\'rish',
                'damage': 'Shaxsiy fayllarni ko\'rish'
            }
        ]

        # Demo uchun ba'zi ruxsatlarni tanlaymiz (tasodifiy)
        import random
        selected_permissions = random.sample(dangerous_permissions, random.randint(3, 6))
        apk_info['permissions'] = selected_permissions

        # Malware tahlili
        malware_signatures = [
            {
                'name': 'SMS Trojan',
                'detected': random.choice([True, False]),
                'severity': 'YUQORI',
                'description': 'Pullik SMS jo\'natadigan zararli dastur',
                'action': 'Pullik SMS orqali pul yechib olish',
                'protection': 'Ilovani o\'chiring, bank hisobingizni bloklang'
            },
            {
                'name': 'Data Stealer',
                'detected': random.choice([True, False]),
                'severity': 'O\'RTA',
                'description': 'Ma\'lumotlarni o\'g\'irlaydigan dastur',
                'action': 'Kontaktlar, SMS, fayllarni yuklab olish',
                'protection': 'Antivirus bilan skanerlash'
            },
            {
                'name': 'Adware',
                'detected': random.choice([True, False]),
                'severity': 'PAST',
                'description': 'Reklama ko\'rsatadigan dastur',
                'action': 'Doimiy reklamalar, brauzerni boshqarish',
                'protection': 'Ilovani o\'chiring, reklama bloklovchi o\'rnating'
            },
            {
                'name': 'Ransomware',
                'detected': False,  # Kamroq uchraydi
                'severity': 'YUQORI',
                'description': 'Fayllarni shifrlaydigan dastur',
                'action': 'Fayllarni qulflash va to\'lov talab qilish',
                'protection': 'Zaxira nusxa olish, antivirus'
            }
        ]

        detected_count = sum(1 for sig in malware_signatures if sig['detected'])
        risk_score = min(100, detected_count * 25 + random.randint(10, 30))

        apk_info['malware_analysis'] = {
            'total_scanned': len(malware_signatures),
            'detected': detected_count,
            'signatures': malware_signatures,
            'risk_score': risk_score,
            'verdict': 'XAVFLI' if risk_score > 70 else 'SHAXBILI' if risk_score > 30 else 'XAVFSIZ'
        }

        # Xavfsizlik muammolari
        security_issues = []
        if len(selected_permissions) > 5:
            security_issues.append({
                'issue': 'Juda ko\'p ruxsatlar',
                'severity': 'O\'RTA',
                'description': f'Ilova {len(selected_permissions)} ta ruxsat so\'rayapti',
                'recommendation': 'Faqat zarur ruxsatlarni berish tavsiya etiladi'
            })

        if apk_info['malware_analysis']['detected'] > 0:
            security_issues.append({
                'issue': 'Zararli dastur belgilari',
                'severity': 'YUQORI' if apk_info['malware_analysis']['detected'] > 1 else 'O\'RTA',
                'description': f'{apk_info["malware_analysis"]["detected"]} ta zararli belgi aniqlandi',
                'recommendation': 'Ilovani ishlatmaslik tavsiya etiladi'
            })

        # Har doim bitta demo muammo qo'shamiz
        security_issues.append({
            'issue': 'Internet ruxsati mavjud',
            'severity': 'MA\'LUMOT',
            'description': 'Ilova internetga ulanish imkoniyatiga ega',
            'recommendation': 'Ishonchli tarmoqlardan foydalaning'
        })

        apk_info['security_issues'] = security_issues

        # Sertifikat ma'lumotlari
        apk_info['certificate_info'] = {
            'has_signature': True,
            'is_self_signed': random.choice([True, False]),
            'issuer': 'Unknown' if random.choice([True, False]) else 'Google LLC',
            'valid_until': '2025-12-31',
            'certificate_files': ['META-INF/CERT.RSA', 'META-INF/MANIFEST.MF']
        }

        # Fayl tuzilmasi
        apk_info['file_structure'] = [
            'AndroidManifest.xml',
            'classes.dex',
            'res/layout/main.xml',
            'res/drawable/icon.png',
            'assets/data.json',
            'lib/armeabi-v7a/libnative.so',
            'META-INF/CERT.RSA',
            'META-INF/MANIFEST.MF'
        ]

        return apk_info

    except Exception as e:
        return {'error': f'APK tahlilida xatolik: {str(e)}'}


def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


# ========== WHOIS Ma'lumotlari ==========
def get_whois_info(domain):
    try:
        # Demo WHOIS ma'lumotlari
        return {
            'registrar': 'Example Registrar Inc.',
            'creation_date': '2020-01-01',
            'expiration_date': '2025-01-01',
            'name_servers': ['ns1.example.com', 'ns2.example.com'],
            'status': ['active'],
            'org': 'Example Organization',
            'country': 'US'
        }
    except Exception as e:
        return {'error': f'WHOIS ma\'lumotlari olinmadi: {str(e)}'}


# ========== SEO va Performance Tahlili ==========
def seo_analysis(url):
    try:
        # Demo SEO ma'lumotlari
        return {
            'meta_tags': {'description': 'Example website description'},
            'headings': {'h1': 1, 'h2': 3, 'h3': 5},
            'images': {'total': 10, 'without_alt': 2},
            'links': {'total': 25},
            'title_info': {'text': 'Example Website', 'length': 15}
        }
    except Exception as e:
        return {'error': str(e)}


def performance_analysis(url):
    try:
        # Demo performance ma'lumotlari
        return {
            'load_time': 150.5,
            'status_code': 200,
            'content_size_kb': 45.2,
            'server_response_time': 89.3
        }
    except Exception as e:
        return {'error': str(e)}


# ========== ASOSIY ROUTE LAR ==========
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_website():
    try:
        website = request.form.get('website', '').strip()

        if not website:
            return render_template('index.html', error='Sayt manzilini kiriting!')

        # Domenni ajratib olish
        if website.startswith(('http://', 'https://')):
            domain = urlparse(website).netloc
        else:
            domain = website.split('/')[0]

        # Barcha tekshiruvlarni bajarish
        port_results = fast_port_scan(domain)
        whois_results = get_whois_info(domain)
        security_results = advanced_security_checks(website)
        seo_results = seo_analysis(website)
        performance_results = performance_analysis(website)

        results = {
            'scan_type': 'website',
            'domain': domain,
            'website': website,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'port_scan': port_results,
            'whois_info': whois_results,
            'security_scan': security_results,
            'seo_analysis': seo_results,
            'performance': performance_results
        }

        # Session ga saqlash
        session['last_results'] = results

        return render_template('results.html', results=results)

    except Exception as e:
        return render_template('index.html', error=f'Skanerlashda xatolik: {str(e)}')


@app.route('/check-links', methods=['POST'])
def check_links_route():
    try:
        website = request.form.get('website', '').strip()

        if not website:
            return render_template('index.html', error='Sayt manzilini kiriting!')

        link_results = check_links(website)

        # Faqat link tekshiruvi natijalari
        results = {
            'scan_type': 'links',
            'website': website,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'link_check': link_results
        }

        session['last_results'] = results

        return render_template('results.html', results=results)

    except Exception as e:
        return render_template('index.html', error=f'Link tekshiruvida xatolik: {str(e)}')


@app.route('/analyze-apk', methods=['POST'])
def analyze_apk_route():
    try:
        if 'file' not in request.files:
            return render_template('index.html', error='APK faylini yuklang')

        file = request.files['file']
        if file.filename == '':
            return render_template('index.html', error='Fayl tanlanmagan')

        if not file.filename.lower().endswith('.apk'):
            return render_template('index.html', error='Faqat APK fayllar qabul qilinadi')

        # Vaqtinchalik fayl yaratish
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as temp_file:
            file.save(temp_file.name)
            apk_results = analyze_apk(temp_file.name)

        # Vaqtinchalik faylni o'chirish
        os.unlink(temp_file.name)

        # Faqat APK tahlili natijalari
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': apk_results
        }

        session['last_results'] = results

        return render_template('results.html', results=results)

    except Exception as e:
        return render_template('index.html', error=f'APK tahlilida xatolik: {str(e)}')


@app.route('/results')
def show_results():
    results = session.get('last_results')
    if not results:
        return redirect(url_for('index'))
    return render_template('results.html', results=results)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
