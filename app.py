# Chrome için 


import requests
import re
import random
import ssl
import socket
import whois as whois_module
import dns.resolver
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import Levenshtein
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager  # Chrome için WebDriver Manager
from selenium.webdriver.chrome.options import Options  # Chrome için Options
from selenium.webdriver.chrome.service import Service  # Chrome için Service
from datetime import datetime, timedelta
import os


class InstagramPhishingDetector:
    def __init__(self):
        self.legitimate_domains = [
            "instagram.com", 
            "www.instagram.com",
            "about.instagram.com",
            "help.instagram.com",
            "business.instagram.com",
            "l.instagram.com"
        ]
        self.suspicious_domains = [
        "trycloudflare.com",
        # İstersen başka şüpheli uzantılar da ekleyebilirsin
        ]
        
        self.suspicious_keywords = [
            "login", "verify", "secure", "account", "ngrok", "password", "confirm", 
            "update", "signin", "auth", "fix", "recover", "alert", "session"
        ]
        
        self.phishing_phrases = [
            "account suspended", "verify your identity", "confirm your account",
            "unusual activity", "security check", "login attempt", "password expired",
            "account locked", "verify now", "limited access"
        ]
        
        self.trusted_issuers = [
            "Let's Encrypt", "DigiCert", "Comodo", "GeoTrust", "Thawte", 
            "GlobalSign", "RapidSSL", "Sectigo", "Amazon", "Google Trust Services"
        ]
        self.shortening_domains = [
            "bit.ly", "tinyurl.com", "rebrand.ly", "tiny.cc", "veshort.com", 
            "t2mio.com", "ow.ly", "bl.ink", "is.gd", "short.io", "cutt.ly"
        ]
            
        self.chrome_options = Options()  # Chrome için Options
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        self.chrome_options.add_argument("--disable-extensions")
        self.chrome_options.add_argument("--disable-infobars")
        self.chrome_options.add_argument("--disable-notifications")
        self.chrome_options.add_argument("--disable-popup-blocking")
        self.chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        self.chrome_options.add_experimental_option("useAutomationExtension", False)

    def analyze_url(self, url):
        """Main method to analyze a URL for phishing indicators"""
        print(f"\n[*] Analyzing URL: {url}")
        
        # Varsayılan details yapısı
        default_details = {
            "domain_analysis": {},
            "url_analysis": {},
            "ssl_analysis": {},
            "content_analysis": {},
            "honey_credentials_test": {}
        }
        
        # Orijinal URL’yi parse et
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return {
                "is_phishing": True,
                "confidence": 1.0,
                "reason": "Invalid URL format",
                "details": default_details
            }
        
        original_domain = parsed_url.netloc.lower()
        if original_domain.startswith("www."):
            original_domain = original_domain[4:]
        
        # Şüpheli alan adı kontrolü
        for suspicious_domain in self.suspicious_domains:
            if suspicious_domain in original_domain:
                default_details["domain_analysis"] = {
                    "suspicious_domain": {
                        "detected": True,
                        "matched_domain": suspicious_domain
                    }
                }
                return {
                    "is_phishing": True,
                    "confidence": 0.95,
                    "reason": f"Şüpheli alan adı '{suspicious_domain}' tespit edildi",
                    "details": default_details
                }
        
        # Kısaltılmış URL mi kontrol et
        is_shortened = original_domain in self.shortening_domains
        
        # Yönlendirmeleri takip et ve nihai URL’yi al
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            final_url = response.url
            final_parsed = urlparse(final_url)
            final_domain = final_parsed.netloc.lower()
            if final_domain.startswith("www."):
                final_domain = final_domain[4:]
        except Exception as e:
            final_url = url
            final_parsed = parsed_url
            final_domain = original_domain
        
        # Kısaltılmış URL ise ve nihai domain Instagram değilse, direkt phishing
        if is_shortened and final_domain not in self.legitimate_domains:
            return {
                "is_phishing": True,
                "confidence": 0.9,
                "reason": "Kısaltılmış URL Instagram dışı bir domaine yönlendiriyor",
                "details": {
                    "shortening_service": original_domain,
                    "final_domain": final_domain
                }
            }
        
        # Analizi nihai URL üzerinden yap
        domain = final_domain
        url = final_url
        parsed_url = final_parsed
        
        # Resmi Instagram domain kontrolü
        if domain in self.legitimate_domains:
            domain_score, domain_details = self._analyze_domain(domain)
            url_score, url_details = self._analyze_url_structure(url)
            default_details["domain_analysis"] = domain_details
            default_details["url_analysis"] = url_details
            return {
                "is_phishing": False,
                "confidence": 0.95,
                "reason": "Resmi Instagram domaini",
                "details": default_details
            }
        
        # Bireysel analizleri çalıştır
        domain_score, domain_details = self._analyze_domain(domain)
        url_score, url_details = self._analyze_url_structure(url)
        ssl_score, ssl_details = self._analyze_ssl(domain)
        
        default_details["domain_analysis"] = domain_details
        default_details["url_analysis"] = url_details
        default_details["ssl_analysis"] = ssl_details
        
        # İlk skor hesaplama
        preliminary_score = (
            domain_score * 0.4 + 
            url_score * 0.3 + 
            ssl_score * 0.3
        )
        
        # Eğer ilk skor çok düşükse, içerik analizine gerek yok
        if preliminary_score < 0.2:
            return {
                "is_phishing": True,
                "confidence": 0.9,
                "reason": "Çok şüpheli URL ve domain özellikleri",
                "details": default_details
            }
        
        # İçerik analizi
        content_score, content_details = self._analyze_content(url)
        default_details["content_analysis"] = content_details
        
        # Nihai skor hesaplama
        final_score = (
            domain_score * 0.3 + 
            url_score * 0.2 + 
            ssl_score * 0.2 + 
            content_score * 0.3
        )
        
        # Şüpheliyse honey credentials testi
        is_confirmed_phishing = False
        honey_pot_details = {}
        
        if final_score < 0.6:
            is_confirmed_phishing, honey_pot_details = self._test_honey_credentials(url)
            default_details["honey_credentials_test"] = honey_pot_details
            if is_confirmed_phishing:
                final_score = 0.0
        
        # Sonuç
        is_phishing = final_score < 0.7 or is_confirmed_phishing
        
        return {
            "is_phishing": is_phishing,
            "confidence": 1 - final_score if is_phishing else final_score,
            "reason": "Şüpheli site tespit edildi: Güvenlik riski mevcut" if is_phishing else "Güvenilir site: Risk bulunamadı",
            "details": default_details
        }
    
    def _analyze_domain(self, domain):
        """Analyze domain for phishing indicators"""
        score = 1.0
        details = {}
        
        # Şüpheli alan adı kontrolü
        suspicious_domain_score = 1.0
        for suspicious_domain in self.suspicious_domains:
            if suspicious_domain in domain:
                suspicious_domain_score = 0.2  # Şüpheli alan adı bulunduğu için skoru düşür
                details["suspicious_domain"] = {
                    "detected": True,
                    "matched_domain": suspicious_domain,
                    "score": suspicious_domain_score,
                    "note": f"Şüpheli alan adı '{suspicious_domain}' tespit edildi"
                }
                break
        else:
            details["suspicious_domain"] = {
                "detected": False,
                "score": suspicious_domain_score
            }
        score *= suspicious_domain_score
        
       
        typo_score = 1.0
        min_distance = float('inf')
        closest_domain = None
        
        for legit_domain in self.legitimate_domains:
            distance = Levenshtein.distance(domain, legit_domain)
            if distance < min_distance:
                min_distance = distance
                closest_domain = legit_domain
        
        
        if closest_domain:
            max_len = max(len(domain), len(closest_domain))
            normalized_distance = min_distance / max_len if max_len > 0 else 1
            
            
            if 0 < normalized_distance < 0.3:
                typo_score = 0.2  # muhtemel typosquatting
            elif normalized_distance < 0.5:
                typo_score = 0.5  # biraz şüpheli
        
        details["typosquatting"] = {
            "score": typo_score,
            "closest_legitimate_domain": closest_domain,
            "normalized_distance": normalized_distance
        }
        score *= typo_score
        
        # zayıf kod homografik saldırı kontrolü
        if domain.startswith("xn--"):
            score *= 0.3
            details["punycode"] = {
                "detected": True,
                "impact": "Severe (-70%)"
            }
        else:
            details["punycode"] = {
                "detected": False
            }
        
        # domain yaşı kontrolü
        domain_age_score = 1.0
        try:
            domain_info = whois_module.whois(domain)
            if domain_info.creation_date:
                
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age_days = (datetime.now() - creation_date).days
                
                if age_days < 30:
                    domain_age_score = 0.2  # çok yeni alan adı varsa bu fazla şüpheli
                elif age_days < 90:
                    domain_age_score = 0.4
                elif age_days < 180:
                    domain_age_score = 0.6
                elif age_days < 365:
                    domain_age_score = 0.8
                
                details["domain_age"] = {
                    "creation_date": str(creation_date),
                    "age_days": age_days,
                    "score": domain_age_score
                }
            else:
                domain_age_score = 0.4  
                details["domain_age"] = {
                    "creation_date": None,
                    "score": domain_age_score,
                    "note": "No creation date found which is unusual"
                }
        except Exception as e:
            domain_age_score = 0.5  
            details["domain_age"] = {
                "error": str(e),
                "score": domain_age_score,
                "note": "Unable to retrieve domain information"
            }
        
        score *= domain_age_score
        
        # Check DNS records
        dns_score = 1.0
        try:
            ns_records = list(dns.resolver.resolve(domain, 'NS'))
            ns_count = len(ns_records)
            
            if ns_count == 0:
                dns_score = 0.3  
            elif ns_count < 2:
                dns_score = 0.7  
            
            details["dns"] = {
                "ns_records": [str(record) for record in ns_records],
                "count": ns_count,
                "score": dns_score
            }
        except Exception as e:
            dns_score = 0.5  # DNS çözümleme başarısız , orta derece şüpheli
            details["dns"] = {
                "error": str(e),
                "score": dns_score,
                "note": "Unable to resolve DNS records"
            }
        
        score *= dns_score
        
        return score, details
    
    def _analyze_url_structure(self, url):
        """Analyze URL structure for phishing indicators"""
        score = 1.0
        details = {}
        
        parsed_url = urlparse(url)
        path = parsed_url.path
        query = parsed_url.query
        hostname = parsed_url.netloc.lower()
        
        # Şüpheli kelimeler için daha sert ceza
        suspicious_word_count = 0
        found_keywords = []
        
        for keyword in self.suspicious_keywords:
            if keyword in hostname + path + query:
                suspicious_word_count += 1
                found_keywords.append(keyword)
        
        if suspicious_word_count > 0:
            keyword_penalty = min(0.2 * suspicious_word_count, 0.8)  # Ceza artırıldı: 0.1 -> 0.2, max 0.6 -> 0.8
            score -= keyword_penalty
            details["suspicious_keywords"] = {
                "found": found_keywords,
                "count": suspicious_word_count,
                "penalty": keyword_penalty
            }
        else:
            details["suspicious_keywords"] = {
                "found": [],
                "count": 0,
                "penalty": 0
            }
        
        # Alt alan adları için eşik düşürüldü ve ceza artırıldı
        subdomain_parts = hostname.split('.')
        subdomain_count = len(subdomain_parts) - 2 if len(subdomain_parts) > 2 else 0
        
        if subdomain_count > 1:  # Eşik 2’den 1’e düşürüldü
            score -= 0.4  # Ceza 0.2 -> 0.4
            details["subdomains"] = {
                "count": subdomain_count,
                "parts": subdomain_parts,
                "penalty": 0.4,
                "note": "Fazla alt alan adı tespit edildi"
            }
        else:
            details["subdomains"] = {
                "count": subdomain_count,
                "parts": subdomain_parts,
                "penalty": 0
            }
        
        # Instagram alt alan adı kontrolü
        if "instagram" in hostname and "instagram.com" not in hostname:
            score -= 0.5  # Ceza 0.3 -> 0.5
            details["brand_in_subdomain"] = {
                "detected": True,
                "penalty": 0.5,
                "note": "Instagram adı alt alan adında ama ana domainde değil"
            }
        else:
            details["brand_in_subdomain"] = {
                "detected": False,
                "penalty": 0
            }
        
        # Kodlanmış karakterler için eşik düşürüldü
        encoded_char_count = path.count('%')
        if encoded_char_count > 1:  # Eşik 3 -> 1
            encoded_penalty = min(0.2 * (encoded_char_count - 1), 0.5)  # Ceza artırıldı
            score -= encoded_penalty
            details["encoded_characters"] = {
                "count": encoded_char_count,
                "penalty": encoded_penalty,
                "note": "Fazla URL kodlanmış karakter"
            }
        else:
            details["encoded_characters"] = {
                "count": encoded_char_count,
                "penalty": 0
            }
        
        # Sorgu parametreleri için eşik düşürüldü
        query_params = parse_qs(query)
        param_count = len(query_params)
        
        if param_count > 3:  # Eşik 5 -> 3
            param_penalty = min(0.2 * (param_count - 3), 0.5)  # Ceza artırıldı
            score -= param_penalty
            details["query_parameters"] = {
                "count": param_count,
                "parameters": list(query_params.keys()),
                "penalty": param_penalty,
                "note": "Fazla sorgu parametresi"
            }
        else:
            details["query_parameters"] = {
                "count": param_count,
                "parameters": list(query_params.keys()),
                "penalty": 0
            }
        
        # Yol derinliği için eşik düşürüldü
        path_parts = [p for p in path.split('/') if p]
        if len(path_parts) > 2:  # Eşik 3 -> 2
            path_penalty = 0.3  # Ceza 0.1 -> 0.3
            score -= path_penalty
            details["path_depth"] = {
                "depth": len(path_parts),
                "parts": path_parts,
                "penalty": path_penalty,
                "note": "Derin URL yapısı"
            }
        else:
            details["path_depth"] = {
                "depth": len(path_parts),
                "parts": path_parts,
                "penalty": 0
            }
        
        score = max(0, score)
        
        return score, details
    
    def _analyze_ssl(self, domain):
        """Analyze SSL certificate for phishing indicators"""
        score = 1.0
        details = {
            "has_https": False,
            "certificate_valid": False,
            "trusted_issuer": False,
            "expires_soon": False
        }
        
        # Check if domain supports HTTPS
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    details["has_https"] = True
                    
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    
        
                    now = datetime.now()
                    if now < not_before or now > not_after:
                        score *= 0.3
                        details["certificate_valid"] = False
                        details["validity_issue"] = "Certificate not currently valid"
                    else:
                        details["certificate_valid"] = True
                    
                    # Check if certificate expires soon
                    if not_after - now < timedelta(days=30):
                        score *= 0.8
                        details["expires_soon"] = True
                        details["expiration_date"] = str(not_after)
                    else:
                        details["expiration_date"] = str(not_after)
                    
                    # Check issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    issuer_o = issuer.get('organizationName', '')
                    
                    details["issuer"] = issuer_o
                    
                    if any(trusted in issuer_o for trusted in self.trusted_issuers):
                        details["trusted_issuer"] = True
                    else:
                        score *= 0.7
                        details["trusted_issuer"] = False
                    
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            # 
            score = 0.4
            details["has_https"] = False
            details["error"] = "Could not establish HTTPS connection"
        except ssl.SSLError as e:
            # ssl hatası geçersiz olma durumu felan
            score = 0.3
            details["has_https"] = True
            details["certificate_valid"] = False
            details["error"] = f"SSL error: {str(e)}"
        except Exception as e:
            # diğer hata
            score = 0.5
            details["error"] = f"Unknown error checking SSL: {str(e)}"
        
        return score, details
    
    def _analyze_content(self, url):
        """Analyze page content for phishing indicators"""
        score = 1.0
        details = {}
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                return 0.5, {"error": f"HTTP status code: {response.status_code}"}
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Login formları için daha katı kontrol
            forms = soup.find_all('form')
            login_forms = []
            
            for form in forms:
                password_inputs = form.find_all('input', {'type': 'password'})
                if password_inputs:
                    login_form = {
                        "inputs": len(form.find_all('input')),
                        "has_password": True,
                        "action": form.get('action', ''),
                        "method": form.get('method', 'get').lower()
                    }
                    login_forms.append(login_form)
            
            details["login_forms"] = login_forms
            
            if login_forms:
                has_suspicious_form = False
                
                for form in login_forms:
                    if form["inputs"] <= 4:  # Eşik 3 -> 4, ama hassasiyet artırıldı
                        has_suspicious_form = True
                        break
                
                if has_suspicious_form:
                    score *= 0.4  # Ceza 0.6 -> 0.4 (daha sert)
                    details["suspicious_forms"] = {
                        "detected": True,
                        "impact": "Çok yüksek (-60%)",
                        "reason": "Şüpheli login formu tespit edildi"
                    }
                else:
                    details["suspicious_forms"] = {
                        "detected": False
                    }
            
            # Instagram markası kontrolü
            instagram_indicators = [
                soup.find_all('img', {'src': re.compile('instagram|insta', re.I)}),
                soup.find_all(string=re.compile('instagram', re.I)),
                soup.find_all('img', {'alt': re.compile('instagram|logo', re.I)})
            ]
            
            has_instagram_branding = any(len(indicator) > 0 for indicator in instagram_indicators)
            details["instagram_branding"] = {
                "detected": has_instagram_branding
            }
            
            if not has_instagram_branding and "instagram" in url.lower():
                score *= 0.5  # Ceza 0.7 -> 0.5
                details["instagram_branding"]["impact"] = "Yüksek (-50%)"
                details["instagram_branding"]["reason"] = "URL’de Instagram var ama markalama yok"
            
            # Dış scriptler için eşik düşürüldü
            external_scripts = soup.find_all('script', {'src': re.compile('^https?://')})
            if len(external_scripts) > 3:  # Eşik 5 -> 3
                score *= 0.6  # Ceza 0.8 -> 0.6
                details["external_scripts"] = {
                    "count": len(external_scripts),
                    "impact": "Yüksek (-40%)",
                    "reason": "Fazla dış script"
                }
            else:
                details["external_scripts"] = {
                    "count": len(external_scripts),
                    "impact": "Yok"
                }
            
            # Gizli elementler için eşik düşürüldü
            hidden_elements = soup.find_all(style=re.compile('display:\\s*none|visibility:\\s*hidden'))
            if len(hidden_elements) > 1:  # Eşik 3 -> 1
                score *= 0.5  # Ceza 0.7 -> 0.5
                details["hidden_elements"] = {
                    "count": len(hidden_elements),
                    "impact": "Yüksek (-50%)",
                    "reason": "Birden fazla gizli element"
                }
            else:
                details["hidden_elements"] = {
                    "count": len(hidden_elements),
                    "impact": "Yok"
                }
            
            # Aciliyet dili için daha sert ceza
            text_content = soup.get_text().lower()
            urgency_score = 0
            found_urgency_phrases = []
            
            for phrase in self.phishing_phrases:
                if phrase.lower() in text_content:
                    urgency_score += 1
                    found_urgency_phrases.append(phrase)
            
            if urgency_score > 0:
                urgency_penalty = min(0.2 * urgency_score, 0.7)  # Ceza artırıldı: max 0.5 -> 0.7
                score *= (1 - urgency_penalty)
                details["urgency_language"] = {
                    "detected": True,
                    "phrases": found_urgency_phrases,
                    "impact": f"Çok yüksek (-{int(urgency_penalty*100)}%)",
                    "reason": "Aciliyet yaratan dil tespit edildi"
                }
            else:
                details["urgency_language"] = {
                    "detected": False,
                    "impact": "Yok"
                }
        
        except Exception as e:
            score = 0.5
            details = {
                "login_forms": [],
                "suspicious_forms": {"detected": False},
                "instagram_branding": {"detected": False},
                "external_scripts": {"count": 0, "impact": "Yok"},
                "hidden_elements": {"count": 0, "impact": "Yok"},
                "urgency_language": {"detected": False, "impact": "Yok"},
                "error": "İçerik analizi yapılamadı: Bağlantı hatası"
            }
        
        return score, details
    
    def _test_honey_credentials(self, url):
        """Test with fake credentials to detect phishing behavior."""
        details = {
            "test_performed": False,
            "credentials_accepted": False,
            "redirected": False,
            "two_factor_detected": False,
            "two_factor_accepted_fake_code": False,
            "redirected_to_legit_instagram_without_2fa": False,
            "redirected_to_legit_instagram": False
        }
        
        driver = None
        try:
            print("WebDriver başlatılıyor...")
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=self.chrome_options)
            print("WebDriver başlatıldı.")
            
            fake_username = f"test_user_{random.randint(10000, 99999)}"
            fake_password = f"TestP@ss{random.randint(10000, 99999)}"
            
            driver.get(url)
            details["test_performed"] = True
            
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            username_field = None
            password_field = None
            for selector in [
                "input[name='username']", "input[name='email']", 
                "input[type='text']", "input[type='email']"
            ]:
                try:
                    username_field = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except NoSuchElementException:
                    continue
            
            for selector in ["input[name='password']", "input[type='password']"]:
                try:
                    password_field = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except NoSuchElementException:
                    continue
            
            if not (username_field and password_field):
                details["error"] = "Kullanıcı adı veya şifre alanı bulunamadı"
                return False, details
            
            username_field.send_keys(fake_username)
            password_field.send_keys(fake_password)
            
            submit_button = None
            for selector in ["button[type='submit']", "input[type='submit']", "button", ".btn", "a.login"]:
                try:
                    submit_button = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except NoSuchElementException:
                    continue
            
            if not submit_button:
                details["error"] = "Gönder butonu bulunamadı"
                return False, details
            
            original_url = driver.current_url
            submit_button.click()
            WebDriverWait(driver, 10).until(lambda d: d.current_url != original_url or EC.presence_of_element_located((By.TAG_NAME, "body")))
            
            current_url = driver.current_url
            details["redirected"] = original_url != current_url
            details["original_url"] = original_url
            details["current_url"] = current_url
            
            page_content = driver.page_source.lower()
            
            success_indicators = ["/home", "/feed", "/timeline", "/dashboard", "success", "welcome", "account", "profile"]
            content_success_indicators = ["welcome", "logged in", "successful", "dashboard", "feed", "timeline", "profile"]
            error_indicators = ["incorrect", "invalid", "failed", "wrong", "error", "not recognized", "try again"]
            two_factor_indicators = [
                "verification code", "two-factor", "2fa", "security code", "sms", "email verification", 
                "doğrulama", "iki adımda doğrulama", "güvenlik kodu", "güvenlik doğrulaması", "doğrulama kodu",
                "enter code", "confirm your identity", "additional verification"
            ]
            
            url_changed_to_success = any(indicator in current_url.lower() for indicator in success_indicators)
            content_indicates_success = any(indicator in page_content for indicator in content_success_indicators)
            has_error_message = any(indicator in page_content for indicator in error_indicators)
            
            # Instagram domainine yönlendirme kontrolü (genel)
            redirected_to_legit_instagram = any(domain in current_url.lower() for domain in self.legitimate_domains)
            
            # 2FA olmadan direkt Instagram'a yönlendirme kontrolü
            two_factor_detected = any(indicator in page_content for indicator in two_factor_indicators)
            details["two_factor_detected"] = two_factor_detected
            
            if redirected_to_legit_instagram and not has_error_message:
                details["redirected_to_legit_instagram"] = True
                if not two_factor_detected:
                    details["redirected_to_legit_instagram_without_2fa"] = True
                    details["note"] = "Sahte kimlik bilgileriyle 2FA olmadan resmi Instagram domainine yönlendirme - bu bir phishing göstergesidir"
                    credentials_accepted = True  # 2FA olmadan Instagram'a gidiyorsa phishing
                else:
                    details["redirected_to_legit_instagram_without_2fa"] = False
                    details["note"] = "Sahte kimlik bilgileriyle resmi Instagram domainine yönlendirme, ancak 2FA tespit edildi"
                    credentials_accepted = True  # 2FA ile Instagram'a gidiyorsa da phishing
            else:
                details["redirected_to_legit_instagram_without_2fa"] = False
                credentials_accepted = (url_changed_to_success or content_indicates_success) and not has_error_message
            
            details["credentials_accepted"] = credentials_accepted
            details["url_changed_to_success"] = url_changed_to_success
            details["content_indicates_success"] = content_indicates_success
            details["has_error_message"] = has_error_message
            
            # 2FA varsa kontrol et
            if two_factor_detected:
                code_field = None
                for selector in [
                    "input[name='code']", "input[name='verification']", "input[type='text']", 
                    "input[type='number']", "input[placeholder*='code']"
                ]:
                    try:
                        code_field = driver.find_element(By.CSS_SELECTOR, selector)
                        break
                    except NoSuchElementException:
                        continue
                
                if code_field:
                    fake_code = f"{random.randint(100000, 999999)}"
                    code_field.send_keys(fake_code)
                    
                    twofa_submit_button = None
                    for selector in ["button[type='submit']", "input[type='submit']", "button", ".btn", ".verify"]:
                        try:
                            twofa_submit_button = driver.find_element(By.CSS_SELECTOR, selector)
                            break
                        except NoSuchElementException:
                            continue
                    
                    if twofa_submit_button:
                        twofa_submit_button.click()
                        WebDriverWait(driver, 10).until(lambda d: d.current_url != current_url or EC.presence_of_element_located((By.TAG_NAME, "body")))
                        
                        new_url = driver.current_url
                        new_page_content = driver.page_source.lower()
                        
                        twofa_url_changed = new_url != current_url
                        twofa_success = any(indicator in new_url.lower() for indicator in success_indicators) or \
                                        any(indicator in new_page_content for indicator in content_success_indicators)
                        twofa_error = any(indicator in new_page_content for indicator in error_indicators)
                        
                        details["two_factor_accepted_fake_code"] = twofa_success and not twofa_error
                        details["twofa_current_url"] = new_url
                        details["twofa_url_changed"] = twofa_url_changed
                        details["twofa_final_url"] = new_url
            
            return credentials_accepted or details["two_factor_accepted_fake_code"], details
        
        except Exception as e:
            print(f"Hata oluştu: {str(e)}")
            details["error"] = f"Hata oluştu: {str(e)}"
            return False, details
        
        finally:
            if driver is not None:
                print("Driver kapatılıyor...")
                driver.quit()
                print("Driver kapatıldı.")
            else:
                print("Driver None, kapatma yapılmadı.")
    
    # scan_url metodunun ilgili kısmı
    def scan_url(self, url):
            """User-friendly method to analyze a URL and display results"""
            print("\n" + "="*60)
            print("🔍 INSTAGRAM PHISHING SCANNER (Using Chrome)")
            print("="*60)
            print(f"URL: {url}")
            print("-"*60)
            
            try:
                result = self.analyze_url(url)
                
                if result["is_phishing"]:
                    print(f"⚠️  ALERT: PHISHING DETECTED")  
                    print(f"🔒 Confidence: {result['confidence']*100:.1f}%")
                    print(f"📝 Reason: {result['reason']}")
                    print("-"*60)
                    print("📊 Analysis Details:")
                    
                    # Domain Analizi
                    domain_details = result["details"].get("domain_analysis", {})
                    print("\n🌐 Domain Analysis:")
                    if "typosquatting" in domain_details:
                        typo = domain_details["typosquatting"]
                        print(f"  • Similar to: {typo.get('closest_legitimate_domain', 'N/A')}")
                        print(f"  • Similarity: {(1-typo.get('normalized_distance', 1))*100:.1f}%")
                    if "domain_age" in domain_details:
                        age = domain_details["domain_age"]
                        print(f"  • Domain age: {age.get('age_days', 'Unknown')} days" if age.get('age_days') is not None else "  • Domain age: Unknown")
                        if age.get("creation_date"):
                            print(f"  • Creation date: {age.get('creation_date')}")
                        if age.get("registrar"):
                            print(f"  • Registrar: {age.get('registrar')}")
                        if age.get("whois_server"):
                            print(f"  • WHOIS Server: {age.get('whois_server')}")
                        if age.get("note"):
                            print(f"  • Note: {age.get('note')}")
                        if age.get("error"):
                            print(f"  • Error: {age.get('error')}")
                        if age.get("score") is not None:
                            print(f"  • Score: {age.get('score'):.2f}")
                    
                    # URL Analiiz
                    url_details = result["details"].get("url_analysis", {})
                    if "suspicious_keywords" in url_details and url_details["suspicious_keywords"].get("found", []):
                        print(f"\n🔗 Suspicious URL Patterns:")
                        print(f"  • Keywords found: {', '.join(url_details['suspicious_keywords']['found'])}")
                    
                    # Content Analizi
                    content_details = result["details"].get("content_analysis", {})
                    if "suspicious_forms" in content_details and content_details["suspicious_forms"].get("detected", False):
                        print(f"\n📄 Page Content:")
                        print(f"  • Suspicious login form detected")
                    if "urgency_language" in content_details and content_details["urgency_language"].get("detected", False):
                        print(f"  • Urgency language: {', '.join(content_details['urgency_language'].get('phrases', []))}")
                    
                    # Honey Credentials Test
                    honey_details = result["details"].get("honey_credentials_test", {})
                    if honey_details.get("test_performed", False):
                        print(f"\n🍯 Honey Credentials Test:")
                        if honey_details.get("credentials_accepted", False):
                            print(f"  • Fake credentials accepted!")
                        if honey_details.get("redirected", False):
                            print(f"  • Redirected to: {honey_details.get('current_url', 'N/A')}")
                        if honey_details.get("two_factor_detected", False):
                            print(f"  • 2FA screen detected")
                            if honey_details.get("two_factor_accepted_fake_code", False):
                                print(f"  • Fake 2FA code accepted! Definitive phishing proof")
                            else:
                                print(f"  • Fake 2FA code rejected") 
                    
                    print("\n" + "-"*60)
                    print("⚠️  RECOMMENDATION: Do not enter any credentials!")
                
                else:
                    print(f"✅ RESULT: LEGITIMATE SITE")
                    print(f"🔒 Confidence: {result['confidence']*100:.1f}%")
                    print(f"📝 Reason: {result['reason']}")
                    print("-"*60)
                    print("📊 Analysis Details:")
                    
                    # Domain Analizi
                    domain_details = result["details"].get("domain_analysis", {})
                    if "domain_age" in domain_details:
                        age = domain_details["domain_age"]
                        print(f"  • Domain age: {age.get('age_days', 'Unknown')} days" if age.get("creation_date") else "  • Domain age: Unknown")
                    
                    # Honey Credentials Test 
                    honey_details = result["details"].get("honey_credentials_test", {})
                    if honey_details.get("test_performed", False):
                        print(f"\n🍯 Honey Credentials Test:")
                        print(f"  • Fake credentials rejected (expected for legitimate site)")
                        if honey_details.get("two_factor_detected", False):
                            print(f"  • 2FA screen detected, handled correctly")
                
                return result
            
            except Exception as e:
                print(f"❌ ERROR: {str(e)}")
                return {
                    "is_phishing": True,
                    "confidence": 0.7,
                    "reason": f"Error during analysis: {str(e)}",
                    "details": {}
                }


from flask import Flask, request, render_template

app = Flask(__name__)
detector = InstagramPhishingDetector()

@app.route('/', methods=['GET', 'POST'])
def index():
    """Flask endpoint to handle URL analysis and render results"""
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            return render_template('index.html', error="Lütfen bir URL girin!")
        
        try:
            result = detector.analyze_url(url)
            # Tüm analiz detaylarını toplamak için ortak bir details yapısı
            details = {
                "domain_analysis": {},
                "url_analysis": {},
                "ssl_analysis": {},
                "content_analysis": {},
                "honey_credentials_test": {}
            }
            
            # Domain Analizi
            domain_details = result["details"].get("domain_analysis", {})
            if "typosquatting" in domain_details:
                details["domain_analysis"]["typosquatting"] = {
                    "closest_legitimate_domain": domain_details["typosquatting"].get("closest_legitimate_domain", "N/A"),
                    "normalized_distance": domain_details["typosquatting"].get("normalized_distance", 1),
                    "similarity": f"{(1 - domain_details['typosquatting'].get('normalized_distance', 1)) * 100:.1f}%"
                }
            if "domain_age" in domain_details:
                details["domain_analysis"]["domain_age"] = {
                    "age_days": domain_details["domain_age"].get("age_days", "Unknown"),
                    "creation_date": domain_details["domain_age"].get("creation_date", None),
                    "registrar": domain_details["domain_age"].get("registrar", "Unknown"),
                    "whois_server": domain_details["domain_age"].get("whois_server", "Unknown"),
                    "note": domain_details["domain_age"].get("note", None),
                    "error": domain_details["domain_age"].get("error", None),
                    "score": domain_details["domain_age"].get("score", None)
                }
            if "dns" in domain_details:
                details["domain_analysis"]["dns"] = {
                    "count": domain_details["dns"].get("count", "Unknown"),
                    "ns_records": domain_details["dns"].get("ns_records", [])
                }
            
            # URL Analizi
            url_details = result["details"].get("url_analysis", {})
            if "suspicious_keywords" in url_details and url_details["suspicious_keywords"].get("found"):
                details["url_analysis"]["suspicious_keywords"] = {
                    "found": url_details["suspicious_keywords"].get("found", []),
                    "count": url_details["suspicious_keywords"].get("count", 0)
                }
            if "subdomains" in url_details:
                details["url_analysis"]["subdomains"] = {
                    "count": url_details["subdomains"].get("count", 0),
                    "parts": url_details["subdomains"].get("parts", [])
                }
            if "brand_in_subdomain" in url_details:
                details["url_analysis"]["brand_in_subdomain"] = {
                    "detected": url_details["brand_in_subdomain"].get("detected", False)
                }
            if "encoded_characters" in url_details:
                details["url_analysis"]["encoded_characters"] = {
                    "count": url_details["encoded_characters"].get("count", 0)
                }
            if "query_parameters" in url_details:
                details["url_analysis"]["query_parameters"] = {
                    "count": url_details["query_parameters"].get("count", 0),
                    "parameters": url_details["query_parameters"].get("parameters", [])
                }
            if "path_depth" in url_details:
                details["url_analysis"]["path_depth"] = {
                    "depth": url_details["path_depth"].get("depth", 0),
                    "parts": url_details["path_depth"].get("parts", [])
                }
            
            # SSL Analizi
            ssl_details = result["details"].get("ssl_analysis", {})
            details["ssl_analysis"] = {
                "has_https": ssl_details.get("has_https", False),
                "certificate_valid": ssl_details.get("certificate_valid", False),
                "trusted_issuer": ssl_details.get("trusted_issuer", False),
                "expires_soon": ssl_details.get("expires_soon", False),
                "issuer": ssl_details.get("issuer", "Unknown"),
                "expiration_date": ssl_details.get("expiration_date", None),
                "error": ssl_details.get("error", None)
            }
            
            # İçerik Analizi
            content_details = result["details"].get("content_analysis", {})
            if "suspicious_forms" in content_details:
                details["content_analysis"]["suspicious_forms"] = {
                    "detected": content_details["suspicious_forms"].get("detected", False),
                    "reason": content_details["suspicious_forms"].get("reason", None)
                }
            if "instagram_branding" in content_details:
                details["content_analysis"]["instagram_branding"] = {
                    "detected": content_details["instagram_branding"].get("detected", False),
                    "reason": content_details["instagram_branding"].get("reason", None)
                }
            if "external_scripts" in content_details:
                details["content_analysis"]["external_scripts"] = {
                    "count": content_details["external_scripts"].get("count", 0),
                    "reason": content_details["external_scripts"].get("reason", None)
                }
            if "hidden_elements" in content_details:
                details["content_analysis"]["hidden_elements"] = {
                    "count": content_details["hidden_elements"].get("count", 0),
                    "reason": content_details["hidden_elements"].get("reason", None)
                }
            if "urgency_language" in content_details and content_details["urgency_language"].get("detected"):
                details["content_analysis"]["urgency_language"] = {
                    "detected": content_details["urgency_language"].get("detected", False),
                    "phrases": content_details["urgency_language"].get("phrases", []),
                    "reason": content_details["urgency_language"].get("reason", None)
                }
            if "error" in content_details:
                details["content_analysis"]["error"] = content_details["error"]
            
            # Honey Credentials Test
            honey_details = result["details"].get("honey_credentials_test", {})
            if honey_details.get("test_performed"):
                details["honey_credentials_test"] = {
                    "test_performed": True,
                    "credentials_accepted": honey_details.get("credentials_accepted", False),
                    "redirected": honey_details.get("redirected", False),
                    "current_url": honey_details.get("current_url", "N/A") if honey_details.get("redirected") else "No redirect",
                    "two_factor_detected": honey_details.get("two_factor_detected", False),
                    "two_factor_accepted_fake_code": honey_details.get("two_factor_accepted_fake_code", False),
                    "redirected_to_legit_instagram": honey_details.get("redirected_to_legit_instagram", False),
                    "redirected_to_legit_instagram_without_2fa": honey_details.get("redirected_to_legit_instagram_without_2fa", False),
                    "note": honey_details.get("note", None),
                    "error": honey_details.get("error", None)
                }
                if honey_details.get("two_factor_detected"):
                    details["honey_credentials_test"]["two_factor_result"] = "Accepted" if honey_details.get("two_factor_accepted_fake_code") else "Rejected"
            
            # Sonuçları şablona gönder
            return render_template('result.html', url=url, result=result, details=details)
        
        except Exception as e:
            return render_template('index.html', error=f"Hata: {str(e)}")
    
    return render_template('index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Renderın varsayılan portu, düzeltme yaptım burda
    app.run(host='0.0.0.0', port=port, debug=False)  
