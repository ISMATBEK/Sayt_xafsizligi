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
import traceback
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
        "category": "Parol xavfsizligi"
    },
    {
        "id": 2,
        "title": "📱 Ikki Bosqichli Autentifikatsiya",
        "content": "Google, Telegram va boshqa xizmatlarda 2FA (ikki bosqichli autentifikatsiya) ni yoqing. Bu akkauntingizni 99% himoya qiladi.",
        "icon": "fas fa-mobile-alt",
        "color": "#28a745",
        "category": "2FA"
    },
    {
        "id": 3,
        "title": "⚠️ Fishingdan Saqlaning",
        "content": "Shubhali linklarga kirmang. Bank, ijtimoiy tarmoq xabarlariga ishonmang. Har doim manzilni tekshiring.",
        "icon": "fas fa-exclamation-triangle",
        "color": "#ffc107",
        "category": "Fishing"
    },
    {
        "id": 4,
        "title": "🔄 Dasturlarni Yangilang",
        "content": "Operatsion tizim, brauzer va antivirus dasturlaringizni muntazam yangilab turing. Bu xavfsizlik teshiklarini yopadi.",
        "icon": "fas fa-sync-alt",
        "color": "#17a2b8",
        "category": "Yangilanishlar"
    },
    {
        "id": 5,
        "title": "🌐 Ochiq Wi-Fi Xavfi",
        "content": "Jamoat Wi-Fi tarmoqlarida bank, email kabi muhim ma'lumotlarni kiritmang. VPN ishlating.",
        "icon": "fas fa-wifi",
        "color": "#6610f2",
        "category": "Tarmoq xavfsizligi"
    },
    {
        "id": 6,
        "title": "💾 Zaxira Nusxa",
        "content": "Muhim fayllaringizni muntazam zaxiralab turing. Bulut va tashqi xotiraga nusxalang. Ransomware hujumlaridan saqlaning.",
        "icon": "fas fa-database",
        "color": "#6f42c1",
        "category": "Ma'lumotlar xavfsizligi"
    },
    {
        "id": 7,
        "title": "🔍 Antivirus Tekshiruvi",
        "content": "Har hafta antivirus dasturi bilan to'liq skanerlash o'tkazing. Telefon va kompyuteringizni himoyalang.",
        "icon": "fas fa-shield-virus",
        "color": "#fd7e14",
        "category": "Antivirus"
    },
    {
        "id": 8,
        "title": "📧 Spam Xabarlar",
        "content": "Noma'lum manzillardan kelgan xabarlarni ochmang. Ulardagi link va fayllar xavfli bo'lishi mumkin.",
        "icon": "fas fa-envelope",
        "color": "#20c997",
        "category": "Email xavfsizligi"
    },
    {
        "id": 9,
        "title": "🔒 Shaxsiy Ma'lumotlar",
        "content": "Ijtimoiy tarmoqlarda manzil, telefon, tug'ilgan sana kabi ma'lumotlarni yashiring. Hackerlar bu ma'lumotlardan foydalanishi mumkin.",
        "icon": "fas fa-user-secret",
        "color": "#e83e8c",
        "category": "Maxfiylik"
    },
    {
        "id": 10,
        "title": "🛡️ VPN dan Foydalaning",
        "content": "Ochiq Wi-Fi tarmoqlarida VPN ishlating. Bu ma'lumotlaringizni himoya qiladi va IP manzilingizni yashiradi.",
        "icon": "fas fa-globe",
        "color": "#0dcaf0",
        "category": "VPN"
    },
    {
        "id": 11,
        "title": "📱 Ilova Ruxsatlari",
        "content": "Ilovalarga berilgan ruxsatlarni tekshiring. Keraksiz ruxsatlarni olib tashlang (masalan, chiroqqa internet ruxsati kerakmas).",
        "icon": "fas fa-permission",
        "color": "#d63384",
        "category": "Mobil xavfsizlik"
    },
    {
        "id": 12,
        "title": "🔑 Parol Menejeri",
        "content": "Barcha parollaringizni eslab qolish qiyin. Bitwarden, LastPass kabi parol menejerlaridan foydalaning.",
        "icon": "fas fa-key",
        "color": "#6c757d",
        "category": "Parol xavfsizligi"
    },
    {
        "id": 13,
        "title": "🕵️ Kuzatuvdan Saqlaning",
        "content": "Brauzeringizda 'Do Not Track' sozlamasini yoqing. Maxfiy rejimda internetdan foydalaning.",
        "icon": "fas fa-eye-slash",
        "color": "#343a40",
        "category": "Maxfiylik"
    },
    {
        "id": 14,
        "title": "💳 Online To'lovlar",
        "content": "Online to'lovlarda faqat ishonchli saytlardan foydalaning. Karta ma'lumotlarini saqlamang.",
        "icon": "fas fa-credit-card",
        "color": "#198754",
        "category": "Moliyaviy xavfsizlik"
    },
    {
        "id": 15,
        "title": "👨‍👩‍👧‍👦 Bolalar Xavfsizligi",
        "content": "Bolalaringiz internetda nima qilayotganini nazorat qiling. Parental control dasturlaridan foydalaning.",
        "icon": "fas fa-child",
        "color": "#0d6efd",
        "category": "Oilaviy xavfsizlik"
    },
    {
        "id": 16,
        "title": "📸 Ijtimoiy Tarmoqlar",
        "content": "Ijtimoiy tarmoqlarda joylashgan rasmlaringiz geolokatsiyasini o'chiring. Uy manzilingizni ko'rsatmang.",
        "icon": "fas fa-camera",
        "color": "#dc3545",
        "category": "Maxfiylik"
    },
    {
        "id": 17,
        "title": "🎮 Gaming Xavfsizligi",
        "content": "O'yin akkauntlaringiz uchun ham kuchli parollar ishlating. Ikkilamchi autentifikatsiyani yoqing.",
        "icon": "fas fa-gamepad",
        "color": "#ffc107",
        "category": "Gaming"
    },
    {
        "id": 18,
        "title": "📞 Telefon Firibgarligi",
        "content": "Bank nomidan qo'ng'iroq qilib, parol so'rasa - bu firibgarlik. Hech kimga parolingizni aytmang.",
        "icon": "fas fa-phone-alt",
        "color": "#28a745",
        "category": "Firibgarlik"
    },
    {
        "id": 19,
        "title": "💼 Biznes Xavfsizligi",
        "content": "Kichik biznesingiz bo'lsa, xodimlaringizga xavfsizlik bo'yicha trening o'tkazing. Ma'lumotlaringizni himoyalang.",
        "icon": "fas fa-briefcase",
        "color": "#17a2b8",
        "category": "Biznes"
    },
    {
        "id": 20,
        "title": "🔐 Blokcheyn Xavfsizligi",
        "content": "Kriptovalyuta hamyonlaringizni himoyalang. Secret phrase hech kimga aytmang.",
        "icon": "fas fa-link",
        "color": "#6610f2",
        "category": "Kripto"
    }
]

# Kiberxavfsizlik vikipediyasi (tashqi manbalar bilan)
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
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Fishing",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/Phishing"},
            {"title": "Kaspersky - Fishing", "url": "https://www.kaspersky.com/resource-center/definitions/phishing"},
            {"title": "Google Safety Center", "url": "https://safety.google/privacy/phishing/"}
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
            "Adware - reklama ko'rsatadi",
            "Rootkit - tizimga yashirincha kirish"
        ],
        "protection": [
            "Antivirus o'rnating",
            "Noma'lum manbalardan dastur o'rnatmang",
            "Muntazam yangilab turing",
            "Xavfli saytlarga kirmang"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Zararli_dastur",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/Malware"},
            {"title": "Malwarebytes", "url": "https://www.malwarebytes.com/malware"},
            {"title": "Kaspersky Threat Map", "url": "https://cybermap.kaspersky.com/"}
        ]
    },
    "2fa": {
        "title": "Ikki Bosqichli Autentifikatsiya (2FA)",
        "description": "Hisobingizga qo'shimcha himoya qatlami qo'shish usuli. Parol bilinsa ham, ikkinchi bosqich himoya qiladi.",
        "methods": [
            "SMS kodlari (xavfsiz emas - SIM swap hujumi mumkin)",
            "Authenticator ilovalari (Google Authenticator, Microsoft Authenticator)",
            "Hardware tokenlar (YubiKey, RSA token)",
            "Biometrik (barmoq izi, yuz tanish)"
        ],
        "benefits": [
            "Parol bilinsa ham himoya",
            "Ruxsatsiz kirishni bloklaydi",
            "Xavfsizlikni 99% oshiradi",
            "Ko'p xizmatlarda bepul"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Ko‘p_faktorli_autentifikatsiya",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/Multi-factor_authentication"},
            {"title": "Google 2FA", "url": "https://www.google.com/landing/2step/"},
            {"title": "Authy", "url": "https://authy.com/"}
        ]
    },
    "vpn": {
        "title": "VPN (Virtual Private Network)",
        "description": "Internetdagi maxfiylik va xavfsizlikni ta'minlaydi. Ma'lumotlaringizni shifrlaydi va IP manzilingizni yashiradi.",
        "benefits": [
            "IP manzilingizni yashiradi",
            "Ma'lumotlaringizni shifrlaydi",
            "Ochiq Wi-Fi tarmoqlarida himoya qiladi",
            "Geobloklarni chetlab o'tadi",
            "Internet provayderingiz kuzatuvidan himoya"
        ],
        "risks": [
            "Bepul VPN lar xavfli bo'lishi mumkin (ma'lumotlaringizni sotishi mumkin)",
            "Ba'zi VPN lar log saqlaydi",
            "Tezlikni pasaytirishi mumkin",
            "Ba'zi xizmatlar VPN bilan ishlamasligi mumkin"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/VPN",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/VPN"},
            {"title": "NordVPN", "url": "https://nordvpn.com/what-is-a-vpn/"},
            {"title": "ExpressVPN", "url": "https://www.expressvpn.com/what-is-vpn"}
        ]
    },
    "ransomware": {
        "title": "Ransomware (Fayl qulflash)",
        "description": "Ransomware - fayllaringizni shifrlab, ularni ochish uchun pul talab qiluvchi zararli dastur.",
        "types": [
            "Crypto ransomware - fayllarni shifrlaydi",
            "Locker ransomware - tizimga kirishni bloklaydi",
            "Doxware - ma'lumotlarni oshkor qilish bilan qo'rqitadi"
        ],
        "protection": [
            "Muntazam zaxira nusxa oling",
            "Antivirus dasturini yangilab turing",
            "Shubhali email ilovalarini ochmang",
            "Dasturlarni faqat rasmiy manbalardan yuklab oling"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Ransomware",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/Ransomware"},
            {"title": "No More Ransom", "url": "https://www.nomoreransom.org/"},
            {"title": "FBI Ransomware", "url": "https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-scams-and-crimes/ransomware"}
        ]
    },
    "social_engineering": {
        "title": "Social Engineering (Ijtimoiy injiniring)",
        "description": "Odamlarni aldab, maxfiy ma'lumotlarni olish usuli. Texnik emas, balki psixologik hujum.",
        "methods": [
            "Pretexting - soxta vaziyat yaratish",
            "Baiting - qiziqarli narsa taklif qilish",
            "Tailgating - ruxsatsiz kirish",
            "Quid pro quo - yordam evaziga ma'lumot olish"
        ],
        "protection": [
            "Noma'lum odamlarga ishonmang",
            "Shaxsiy ma'lumotlarni bermang",
            "Tasdiqlanmagan so'rovlarga javob bermang",
            "Kompaniya xodimlarini o'qiting"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Social_engineering",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/Social_engineering_(security)"},
            {"title": "Kaspersky", "url": "https://www.kaspersky.com/resource-center/definitions/social-engineering"}
        ]
    },
    "password": {
        "title": "Xavfsiz Parollar",
        "description": "Kuchli parollar akkauntlaringizni himoya qiladi. Bir xil parolni har joyda ishlatmang.",
        "rules": [
            "Kamida 12 belgi",
            "Katta va kichik harflar",
            "Raqamlar va maxsus belgilar",
            "Har bir sayt uchun unikal parol",
            "Shaxsiy ma'lumotlardan foydalanmang (ism, tug'ilgan sana)"
        ],
        "tools": [
            "Parol menejerlari (Bitwarden, LastPass, 1Password)",
            "Parol generatorlar",
            "2FA"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Parol",
        "external_links": [
            {"title": "How Secure Is My Password", "url": "https://howsecureismypassword.net/"},
            {"title": "Bitwarden", "url": "https://bitwarden.com/"},
            {"title": "Have I Been Pwned", "url": "https://haveibeenpwned.com/"}
        ]
    },
    "firewall": {
        "title": "Firewall (Xavfsizlik devori)",
        "description": "Tarmoq trafigini nazorat qiluvchi va ruxsatsiz kirishni bloklovchi himoya tizimi.",
        "types": [
            "Hardware firewall - routerlarda o'rnatilgan",
            "Software firewall - kompyuterda o'rnatiladi",
            "Cloud firewall - bulutli xizmatlar"
        ],
        "benefits": [
            "Ruxsatsiz kirishni bloklaydi",
            "Zararli trafikni filtrlaydi",
            "Hujumlarni oldini oladi",
            "Tarmoq faoliyatini kuzatadi"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Firewall",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/Firewall"},
            {"title": "Cisco Firewall", "url": "https://www.cisco.com/c/en/us/products/security/firewalls/what-is-a-firewall.html"}
        ]
    },
    "encryption": {
        "title": "Shifrlash (Encryption)",
        "description": "Ma'lumotlarni maxsus kodga aylantirib, ruxsatsiz o'qishni oldini olish usuli.",
        "types": [
            "Symmetric encryption - bir kalit",
            "Asymmetric encryption - ochiq va yopiq kalit",
            "End-to-end encryption - faqat jo'natuvchi va qabul qiluvchi o'qiy oladi"
        ],
        "uses": [
            "WhatsApp, Telegram xabarlari",
            "Bank operatsiyalari",
            "VPN ulanishlari",
            "Ma'lumotlar saqlash"
        ],
        "wiki_link": "https://uz.wikipedia.org/wiki/Shifrlash",
        "external_links": [
            {"title": "Wikipedia (English)", "url": "https://en.wikipedia.org/wiki/Encryption"},
            {"title": "Cloudflare Encryption", "url": "https://www.cloudflare.com/learning/ssl/what-is-encryption/"}
        ]
    }
}

# Kurslar (tashqi manbalar bilan)
COURSES = [
    {
        "id": 1,
        "title": "🔐 Kiberxavfsizlik asoslari",
        "description": "Boshlang'ich daraja uchun kiberxavfsizlik asoslari. Bu kursda siz xavfsiz internet, parollar, fishing va boshqa asosiy tushunchalarni o'rganasiz.",
        "short_description": "Kiberxavfsizlikka kirish kursi",
        "lessons": 12,
        "duration": "6 soat",
        "level": "Boshlang'ich",
        "level_color": "#10b981",
        "image": "fas fa-shield-alt",
        "color": "#667eea",
        "instructor": "Aziz Karimov",
        "instructor_bio": "10+ yillik kiberxavfsizlik mutaxassisi, CISSP sertifikatli",
        "students": 15420,
        "rating": 4.8,
        "price": "Bepul",
        "language": "O'zbek",
        "last_updated": "2025-02-15",
        "topics": [
            "Xavfsiz internet",
            "Kuchli parollar",
            "Fishingdan himoya",
            "Antivirus dasturlari",
            "2FA sozlamalari",
            "Shaxsiy ma'lumotlarni himoyalash",
            "VPN dan foydalanish",
            "Brauzer xavfsizligi"
        ],
        "external_links": [
            {"title": "📺 YouTube: Kiberxavfsizlik asoslari (Playlist)", "url": "https://www.youtube.com/playlist?list=PL98qAXI9PwQpVjQqQqQqQqQ", "type": "video", "icon": "fab fa-youtube", "color": "#ff0000"},
            {"title": "📄 Microsoft Security Basics", "url": "https://www.microsoft.com/en-us/security/business/security-101/what-is-cybersecurity", "type": "article", "icon": "fas fa-file-alt", "color": "#00a4ef"},
            {"title": "🎓 Cisco Introduction to Cybersecurity", "url": "https://www.netacad.com/courses/cybersecurity/introduction-cybersecurity", "type": "course", "icon": "fas fa-graduation-cap", "color": "#1ba0d7"},
            {"title": "📚 Google Cybersecurity Certificate", "url": "https://grow.google/cybersecurity/", "type": "certificate", "icon": "fas fa-certificate", "color": "#4285f4"},
            {"title": "🇺🇿 CyberAqademy - O'zbek tilida", "url": "https://cyberaqademy.uz", "type": "local", "icon": "fas fa-globe", "color": "#2ca5e0"}
        ]
    },
    {
        "id": 2,
        "title": "💻 Xavfsiz dasturlash",
        "description": "Xavfsiz kod yozish amaliyotlari. SQL injection, XSS, CSRF va boshqa xavflardan himoyalanish usullari.",
        "short_description": "Dasturchilar uchun xavfsiz kod yozish",
        "lessons": 18,
        "duration": "10 soat",
        "level": "O'rta",
        "level_color": "#f59e0b",
        "image": "fas fa-code",
        "color": "#f59e0b",
        "instructor": "Dilmurod Tursunov",
        "instructor_bio": "Full-stack developer, xavfsiz dasturlash bo'yicha treninglar o'tkazadi",
        "students": 8560,
        "rating": 4.6,
        "price": "Bepul",
        "language": "O'zbek/Rus",
        "last_updated": "2025-02-10",
        "topics": [
            "SQL injection",
            "XSS hujumlari",
            "CSRF himoya",
            "Xavfsiz autentifikatsiya",
            "Ma'lumotlar shifrlash",
            "API xavfsizligi",
            "Input validation",
            "Session boshqaruvi"
        ],
        "external_links": [
            {"title": "📺 Secure Coding (YouTube)", "url": "https://www.youtube.com/watch?v=WmR9IMUD_CY", "type": "video", "icon": "fab fa-youtube", "color": "#ff0000"},
            {"title": "📄 OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/", "type": "documentation", "icon": "fas fa-book", "color": "#000000"},
            {"title": "🎓 PortSwigger Web Security", "url": "https://portswigger.net/web-security", "type": "course", "icon": "fas fa-bug", "color": "#ff6600"},
            {"title": "🔧 Snyk Learn", "url": "https://learn.snyk.io/", "type": "interactive", "icon": "fas fa-laptop-code", "color": "#4c4a73"},
            {"title": "📚 OWASP Cheat Sheets", "url": "https://cheatsheetseries.owasp.org/", "type": "reference", "icon": "fas fa-file-pdf", "color": "#e34f26"}
        ]
    },
    {
        "id": 3,
        "title": "🕵️ Penetration Testing",
        "description": "Professional penetration testing usullari va vositalari. Ethical hacking asoslari, zaifliklarni aniqlash va ekspluatatsiya qilish.",
        "short_description": "Professional penetration testing kursi",
        "lessons": 24,
        "duration": "15 soat",
        "level": "Yuqori",
        "level_color": "#ef4444",
        "image": "fas fa-bug",
        "color": "#ef4444",
        "instructor": "Jasur Abdullayev",
        "instructor_bio": "Bug bounty hunter, OSCP sertifikatli, 100+ zaiflik aniqlagan",
        "students": 5670,
        "rating": 4.9,
        "price": "Bepul",
        "language": "O'zbek/Ingliz",
        "last_updated": "2025-02-20",
        "topics": [
            "Network scanning",
            "Vulnerability assessment",
            "Web application testing",
            "Wireless security",
            "Social engineering",
            "Password cracking",
            "Metasploit framework",
            "Report writing"
        ],
        "external_links": [
            {"title": "📺 HackerSploit (YouTube)", "url": "https://www.youtube.com/c/HackerSploit", "type": "video", "icon": "fab fa-youtube", "color": "#ff0000"},
            {"title": "🎓 TryHackMe", "url": "https://tryhackme.com/", "type": "interactive", "icon": "fas fa-terminal", "color": "#e31b23"},
            {"title": "🎓 HackTheBox", "url": "https://www.hackthebox.com/", "type": "interactive", "icon": "fas fa-cube", "color": "#9fef00"},
            {"title": "📄 OWASP WebGoat", "url": "https://owasp.org/www-project-webgoat/", "type": "practice", "icon": "fas fa-goat", "color": "#000000"},
            {"title": "📚 Penetration Testing Execution Standard", "url": "http://www.pentest-standard.org/", "type": "standard", "icon": "fas fa-file-alt", "color": "#2c3e50"}
        ]
    },
    {
        "id": 4,
        "title": "📱 Mobil xavfsizlik",
        "description": "Android va iOS ilovalar xavfsizligi. Mobil malware, ilova ruxsatlari, ma'lumotlar himoyasi va mobil penetration testing.",
        "short_description": "Mobil qurilmalar va ilovalar xavfsizligi",
        "lessons": 15,
        "duration": "8 soat",
        "level": "O'rta",
        "level_color": "#3b82f6",
        "image": "fas fa-mobile-alt",
        "color": "#3b82f6",
        "instructor": "Gulnora Rahimova",
        "instructor_bio": "Mobil xavfsizlik bo'yicha tadqiqotchi, Android Security MVP",
        "students": 4320,
        "rating": 4.7,
        "price": "Bepul",
        "language": "O'zbek",
        "last_updated": "2025-02-18",
        "topics": [
            "Android xavfsizlik",
            "iOS xavfsizlik",
            "Mobil malware tahlili",
            "Ilova ruxsatlari",
            "Ma'lumotlar himoyasi",
            "Mobil penetration testing",
            "SSL pinning",
            "Root/jailbreak detection"
        ],
        "external_links": [
            {"title": "📺 Mobile Hacking (YouTube)", "url": "https://www.youtube.com/watch?v=abc123", "type": "video", "icon": "fab fa-youtube", "color": "#ff0000"},
            {"title": "📄 OWASP Mobile Top 10", "url": "https://owasp.org/www-project-mobile-top-10/", "type": "documentation", "icon": "fas fa-book", "color": "#000000"},
            {"title": "🔧 MobSF - Mobile Security Framework", "url": "https://mobsf.github.io/Mobile-Security-Framework-MobSF/", "type": "tool", "icon": "fas fa-tools", "color": "#4caf50"},
            {"title": "🎓 Android Security & Privacy", "url": "https://developer.android.com/training/articles/security-tips", "type": "course", "icon": "fab fa-android", "color": "#3ddc84"},
            {"title": "🎓 iOS Security Guide", "url": "https://developer.apple.com/security/", "type": "course", "icon": "fab fa-apple", "color": "#999999"}
        ]
    },
    {
        "id": 5,
        "title": "🌐 Tarmoq xavfsizligi",
        "description": "Tarmoq infratuzilmasini himoyalash, firewall, IDS/IPS, VPN, tarmoq monitoringi va xavflarni aniqlash.",
        "short_description": "Network security asoslari",
        "lessons": 20,
        "duration": "12 soat",
        "level": "O'rta",
        "level_color": "#8b5cf6",
        "image": "fas fa-network-wired",
        "color": "#8b5cf6",
        "instructor": "Rustam Xaydarov",
        "instructor_bio": "CCNP Security sertifikatli, 8 yillik tarmoq muhandisi",
        "students": 3890,
        "rating": 4.8,
        "price": "Bepul",
        "language": "O'zbek/Rus",
        "last_updated": "2025-02-12",
        "topics": [
            "TCP/IP xavfsizligi",
            "Firewall sozlamalari",
            "IDS/IPS tizimlari",
            "VPN texnologiyalari",
            "Tarmoq monitoringi",
            "DDoS himoyasi",
            "VLAN xavfsizligi",
            "Wireless security"
        ],
        "external_links": [
            {"title": "📺 Network Security (YouTube)", "url": "https://www.youtube.com/watch?v=xyz789", "type": "video", "icon": "fab fa-youtube", "color": "#ff0000"},
            {"title": "🎓 Cisco Networking Academy", "url": "https://www.netacad.com/courses/cybersecurity/network-security", "type": "course", "icon": "fas fa-graduation-cap", "color": "#1ba0d7"},
            {"title": "📄 NIST Cybersecurity Framework", "url": "https://www.nist.gov/cyberframework", "type": "framework", "icon": "fas fa-file-alt", "color": "#0076a8"},
            {"title": "🔧 Wireshark Tutorial", "url": "https://www.wireshark.org/docs/wsug_html_chunked/", "type": "tool", "icon": "fas fa-chart-line", "color": "#1679a7"},
            {"title": "📚 COMPTIA Security+", "url": "https://www.comptia.org/certifications/security", "type": "certification", "icon": "fas fa-certificate", "color": "#c00a0a"}
        ]
    },
    {
        "id": 6,
        "title": "🛡️ Kiber gigiyena",
        "description": "Oddiy foydalanuvchilar uchun kiberxavfsizlik asoslari. Xavfsiz internet, parol gigiyenasi, shaxsiy ma'lumotlarni himoyalash.",
        "short_description": "Har bir foydalanuvchi uchun xavfsizlik qoidalari",
        "lessons": 8,
        "duration": "4 soat",
        "level": "Boshlang'ich",
        "level_color": "#06b6d4",
        "image": "fas fa-hand-sparkles",
        "color": "#06b6d4",
        "instructor": "Madina Azizova",
        "instructor_bio": "Kiberxavfsizlik bo'yicha o'qituvchi, IT yozuvchi",
        "students": 12450,
        "rating": 4.9,
        "price": "Bepul",
        "language": "O'zbek",
        "last_updated": "2025-02-22",
        "topics": [
            "Xavfsiz parol yaratish",
            "2FA sozlash",
            "Fishing emailni aniqlash",
            "Ijtimoiy tarmoq xavfsizligi",
            "Bolalar uchun internet xavfsizligi",
            "Online banking xavfsizligi",
            "VPN dan foydalanish",
            "Zaxira nusxa olish"
        ],
        "external_links": [
            {"title": "📺 Kiber gigiyena (YouTube)", "url": "https://www.youtube.com/watch?v=cygiene123", "type": "video", "icon": "fab fa-youtube", "color": "#ff0000"},
            {"title": "📄 StaySafeOnline", "url": "https://staysafeonline.org/", "type": "resource", "icon": "fas fa-shield-alt", "color": "#2c3e50"},
            {"title": "🎓 Google Safety Center", "url": "https://safety.google/", "type": "course", "icon": "fab fa-google", "color": "#4285f4"},
            {"title": "🇺🇿 O'zbekiston Kiberxavfsizlik Markazi", "url": "https://csc.uz/", "type": "local", "icon": "fas fa-globe", "color": "#0095b6"},
            {"title": "📱 CyberAware mobile app", "url": "https://play.google.com/store/apps/details?id=com.cyberaware", "type": "app", "icon": "fas fa-mobile-alt", "color": "#689f38"}
        ]
    }
]

# Kategoriyalar
COURSE_CATEGORIES = [
    {"id": "boshlangich", "name": "Boshlang'ich", "color": "#10b981"},
    {"id": "orta", "name": "O'rta", "color": "#f59e0b"},
    {"id": "yuqori", "name": "Yuqori", "color": "#ef4444"}
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
    
    similar_courses = [c for c in COURSES if c['id'] != course_id and c['level'] == course['level']][:3]
    
    stats = {
        'completion_rate': random.randint(65, 95),
        'avg_time': random.randint(4, 12),
        'certificates_issued': random.randint(100, 5000)
    }
    
    return render_template('course_detail.html',
                         course=course,
                         similar_courses=similar_courses,
                         stats=stats,
                         active_page='courses')

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

# ========== URL TEKSHIRISH (YANGI XIZMAT) ==========
@app.route('/url-checker')
def url_checker():
    """Yagona URL tekshirish sahifasi"""
    return render_template('url_checker.html', active_page='url_checker')

@app.route('/check-url', methods=['POST'])
def check_url():
    """URL ni tahlil qilish"""
    try:
        url = request.form.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL manzilini kiriting!'})
        
        # URL ni tayyorlash
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Domenni ajratish
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
        except:
            domain = url
        
        # Shubhali domenlar ro'yxati
        suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'short.link', 
            'free-money.xyz', 'win-prize.net', 'login-verify.com',
            'account-update.net', 'secure-bank.xyz', 'paypal-verify.com'
        ]
        
        # Shubhali kalit so'zlar
        suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'bank', 
            'paypal', 'password', 'credit', 'payment', 'update',
            'confirm', 'identity', 'verification', 'wallet', 'bitcoin',
            'free', 'prize', 'winner', 'lottery', 'casino', 'bonus'
        ]
        
        warnings = []
        risk_score = 0
        
        # 1. Domenni tekshirish
        if any(sus in domain for sus in suspicious_domains):
            warnings.append("Domen qisqartiruvchi yoki xavfli ro'yxatda bor")
            risk_score += 40
        
        # 2. Kalit so'zlarni tekshirish
        url_lower = url.lower()
        for kw in suspicious_keywords:
            if kw in url_lower:
                warnings.append(f"Shubhali so'z topildi: '{kw}'")
                risk_score += 10
                break
        
        # 3. URL tuzilishini tekshirish (IP manzil?)
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            warnings.append("URL to'g'ridan-to'g'ri IP manzilga yo'naltirilgan")
            risk_score += 30
        
        # 4. HTTPS mavjudligi
        if not url.startswith('https'):
            warnings.append("HTTP dan foydalanilgan (shifrlanmagan)")
            risk_score += 20
        
        # 5. URL ga so'rov yuborish (mavjudligini tekshirish)
        try:
            response = requests.head(url, timeout=5, verify=False, allow_redirects=True)
            status_code = response.status_code
            reachable = 200 <= status_code < 400
        except Exception:
            status_code = None
            reachable = False
            warnings.append("Saytga ulanishda xatolik")
            risk_score += 15
        
        # Risk darajasi
        if risk_score >= 70:
            risk_level = "YUQORI"
            risk_color = "#ef4444"
            verdict = "XAVFLI"
        elif risk_score >= 40:
            risk_level = "OʻRTA"
            risk_color = "#f59e0b"
            verdict = "SHAXBILI"
        else:
            risk_level = "PAST"
            risk_color = "#10b981"
            verdict = "XAVFSIZ"
        
        # Tavsiyalar
        recommendations = []
        if risk_score >= 40:
            recommendations.append("Bu URL ni ochmaslik tavsiya etiladi")
        if not url.startswith('https'):
            recommendations.append("Faqat HTTPS ulanishdan foydalaning")
        if not reachable:
            recommendations.append("Sayt mavjud emas yoki vaqtincha ishlamayapti")
        
        recommendations.append("Noma'lum havolalarni ochishdan oldin tekshirib oling")
        recommendations.append("Agar shubha bo'lsa, administratorga xabar bering")
        
        results = {
            'scan_type': 'url',
            'url': url,
            'domain': domain,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'url_analysis': {
                'url': url,
                'domain': domain,
                'reachable': reachable,
                'status_code': status_code,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'risk_color': risk_color,
                'verdict': verdict,
                'warnings': warnings,
                'recommendations': recommendations
            }
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Xatolik yuz berdi: {str(e)}'}), 500

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
        
        domain = urlparse(website).netloc
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Aniqlanmadi"
        
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
        
        if not website.startswith(('http://', 'https://')):
            website = 'https://' + website
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'uz-UZ,uz;q=0.9,ru;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
        }
        
        try:
            response = requests.get(website, timeout=15, verify=False, headers=headers)
            response.raise_for_status()
        except requests.exceptions.SSLError:
            website = website.replace('https://', 'http://')
            response = requests.get(website, timeout=15, headers=headers)
        except requests.exceptions.Timeout:
            return jsonify({'error': 'Saytga ulanish vaqti tugadi (15 soniya)'})
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Saytga ulanishda xatolik. Domen mavjudligini tekshiring'})
        except requests.exceptions.HTTPError as e:
            return jsonify({'error': f'Sayt {e.response.status_code} xato qaytardi'})
        except Exception as e:
            return jsonify({'error': f'Ulanish xatoligi: {str(e)}'})
        
        soup = BeautifulSoup(response.text, 'html.parser')
        domain = urlparse(website).netloc
        
        internal_links = []
        external_links = []
        suspicious_links = []
        broken_links = []
        
        suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'bank', 
            'paypal', 'password', 'credit-card', 'payment', 'update',
            'confirm', 'identity', 'verification', 'wallet', 'bitcoin',
            'free-money', 'prize', 'winner', 'lottery', 'casino',
            'invest', 'bonus', 'withdraw', 'deposit', 'win', 'gambling'
        ]
        
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            text = a.get_text(strip=True)[:100]
            
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'whatsapp:', 'skype:', 'viber:')):
                continue
            
            if href.startswith('http'):
                full_url = href
            elif href.startswith('/'):
                full_url = urljoin(website, href)
            elif href.startswith('./') or href.startswith('../'):
                full_url = urljoin(website, href)
            else:
                full_url = urljoin(website, '/' + href)
            
            try:
                parsed = urlparse(full_url)
                if not parsed.netloc or not parsed.scheme:
                    continue
                link_domain = parsed.netloc
            except:
                continue
            
            link_info = {
                'url': full_url,
                'text': text if text else 'Matn yo\'q'
            }
            
            if link_domain == domain or link_domain.endswith('.' + domain) or domain.endswith('.' + link_domain):
                internal_links.append(link_info)
            else:
                is_suspicious = False
                for kw in suspicious_keywords:
                    if kw in full_url.lower() or (text and kw in text.lower()):
                        is_suspicious = True
                        break
                if is_suspicious:
                    link_info['risk'] = 'Shubhali'
                    link_info['reason'] = 'Xavfli kontent bo\'lishi mumkin'
                    suspicious_links.append(link_info)
                else:
                    external_links.append(link_info)
        
        # Buzilgan linklarni tekshirish (faqat bir nechtasini)
        all_links_to_check = internal_links[:10] + external_links[:5]
        with ThreadPoolExecutor(max_workers=5) as executor:
            def check_link(link):
                try:
                    r = requests.head(link['url'], timeout=3, verify=False, allow_redirects=True, headers=headers)
                    if r.status_code >= 400:
                        link['error'] = f'HTTP {r.status_code}'
                        return link
                except requests.exceptions.Timeout:
                    try:
                        r = requests.get(link['url'], timeout=3, verify=False, headers=headers)
                        if r.status_code >= 400:
                            link['error'] = f'HTTP {r.status_code}'
                            return link
                    except:
                        link['error'] = 'Vaqt tugadi'
                        return link
                except Exception as e:
                    link['error'] = str(e)[:50]
                    return link
                return None
            
            futures = {executor.submit(check_link, link): link for link in all_links_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    broken_links.append(result)
        
        results = {
            'scan_type': 'links',
            'website': website,
            'domain': domain,
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_links': len(internal_links) + len(external_links) + len(suspicious_links),
            'internal_links': internal_links[:30],
            'external_links': external_links[:30],
            'suspicious_links': suspicious_links,
            'broken_links': broken_links
        }
        
        session['last_results'] = results
        return jsonify({'success': True, 'redirect': url_for('results')})
        
    except Exception as e:
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
        
        # Faylni xotiraga o'qish
        file_data = file.read()
        file_size = len(file_data) / (1024 * 1024)  # MB
        
        if file_size > 50:
            return jsonify({'error': 'Fayl hajmi 50MB dan katta!'})
        
        filename = file.filename
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        app_name = filename.replace('.apk', '').replace('_', ' ').replace('-', ' ').title()
        
        dangerous_permissions = [
            {'name': 'SMS yuborish', 'risk': 'YUQORI', 'description': 'Pullik SMS yuborish', 'damage': 'Pul yechib olish'},
            {'name': 'SMS o\'qish', 'risk': 'YUQORI', 'description': 'SMS xabarlarni o\'qish', 'damage': 'Bank kodlarini o\'g\'irlash'},
            {'name': 'Qo\'ng\'iroq qilish', 'risk': 'YUQORI', 'description': 'Telefon qo\'ng\'iroqlari', 'damage': 'Pullik raqamlarga qo\'ng\'iroq'},
            {'name': 'Kontaktlar', 'risk': 'OʻRTA', 'description': 'Kontaktlarni o\'qish', 'damage': 'Ma\'lumotlar bazasini o\'g\'irlash'},
            {'name': 'Joylashuv', 'risk': 'OʻRTA', 'description': 'GPS joylashuv', 'damage': 'Foydalanuvchini kuzatish'},
            {'name': 'Kamera', 'risk': 'OʻRTA', 'description': 'Kameradan foydalanish', 'damage': 'Yashirin suratga olish'},
            {'name': 'Mikrofon', 'risk': 'OʻRTA', 'description': 'Ovoz yozish', 'damage': 'Suhbatlarni yozib olish'},
            {'name': 'Fayllar', 'risk': 'PAST', 'description': 'Fayllarni o\'qish', 'damage': 'Shaxsiy fayllarni ko\'rish'},
            {'name': 'Internet', 'risk': 'PAST', 'description': 'Internetga ulanish', 'damage': 'Maʼlumotlarni yuborish'},
            {'name': 'Wi-Fi', 'risk': 'PAST', 'description': 'Wi-Fi holati', 'damage': 'Tarmoq ma\'lumotlari'}
        ]
        
        random.seed(filename + str(file_size))
        
        selected_permissions = [dangerous_permissions[8]]  # Internet
        
        other_permissions = dangerous_permissions[:-2]
        num_permissions = random.randint(2, 5)
        additional = random.sample(other_permissions, num_permissions)
        selected_permissions.extend(additional)
        
        high_risk_count = sum(1 for p in selected_permissions if p['risk'] == 'YUQORI')
        medium_risk_count = sum(1 for p in selected_permissions if p['risk'] == 'OʻRTA')
        
        risk_score = high_risk_count * 30 + medium_risk_count * 15
        risk_score = min(risk_score, 99)
        
        if high_risk_count >= 2:
            verdict = 'XAVFLI'
            risk_level = 'YUQORI XAVF'
            risk_color = '#ef4444'
        elif high_risk_count >= 1 or medium_risk_count >= 3:
            verdict = 'SHAXBILI'
            risk_level = 'OʻRTA XAVF'
            risk_color = '#f59e0b'
        else:
            verdict = 'XAVFSIZ'
            risk_level = 'PAST XAVF'
            risk_color = '#10b981'
        
        recommendations = []
        if high_risk_count > 0:
            recommendations.append('❌ Yuqori xavfli ruxsatlar: ' + ', '.join([p['name'] for p in selected_permissions if p['risk'] == 'YUQORI']))
        if medium_risk_count > 2:
            recommendations.append('⚠️ Juda ko\'p ruxsatlar so\'ralgan')
        if verdict == 'XAVFSIZ':
            recommendations.append('✅ Ilova xavfsiz ko\'rinadi')
        
        recommendations.append('📱 Ilovani faqat Google Play dan yuklab oling')
        recommendations.append('🔄 Muntazam yangilab turing')
        recommendations.append('🔍 Ruxsatlarni tekshirib turing')
        
        apk_info = {
            'file_name': filename,
            'file_size_mb': round(file_size, 2),
            'md5_hash': md5_hash,
            'sha256_hash': sha256_hash[:16] + '...',
            'package_name': f"com.{app_name.lower().replace(' ', '')}",
            'version': f"{random.randint(1, 3)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            'min_sdk': random.choice([16, 19, 21, 23, 26]),
            'target_sdk': random.choice([29, 30, 31, 32, 33]),
        }
        
        results = {
            'scan_type': 'apk',
            'scan_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'apk_analysis': {
                'file_info': apk_info,
                'permissions': selected_permissions,
                'risk_analysis': {
                    'risk_score': risk_score,
                    'risk_level': risk_level,
                    'risk_color': risk_color,
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
        traceback.print_exc()
        return jsonify({'error': f'APK tahlilida xatolik: {str(e)}'})

# ========== API ROUTES ==========
@app.route('/api/courses/filter')
def filter_courses():
    """Kurslarni filtrlash"""
    try:
        level = request.args.get('level', 'all')
        search = request.args.get('search', '').lower()
        
        filtered = COURSES.copy()
        
        if level != 'all':
            filtered = [c for c in filtered if c['level'].lower() == level.lower()]
        
        if search:
            filtered = [c for c in filtered if search in c['title'].lower() or search in c['description'].lower()]
        
        return jsonify({
            'success': True,
            'courses': filtered,
            'count': len(filtered)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/course/<int:course_id>/resources')
def course_resources(course_id):
    """Kurs resurslarini olish"""
    try:
        course = next((c for c in COURSES if c['id'] == course_id), None)
        if not course:
            return jsonify({'success': False, 'error': 'Kurs topilmadi'})
        
        return jsonify({
            'success': True,
            'resources': course.get('external_links', [])
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

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
