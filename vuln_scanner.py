import tkinter as tk
from tkinter import messagebox  # Import messagebox for showing temporary messages
import requests
from bs4 import BeautifulSoup
import urllib.parse

# Function to show scanning message
def show_scanning_message():
    messagebox.showinfo("Scanning", "Scanning the Web-Site...")

# Function to perform SQL Injection test
def test_sql_injection(url):
    payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR '1'='1' /*"]
    for payload in payloads:
        target_url = f"{url}{urllib.parse.quote(payload)}"
        response = requests.get(target_url)
        if "error" in response.text or "syntax" in response.text:
            return True
    return False

# Function to perform XSS test
def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    target_url = f"{url}{urllib.parse.quote(payload)}"
    response = requests.get(target_url)
    if payload in response.text:
        return True
    return False

# Function to perform Command Injection test
def test_command_injection(url):
    payload = "; ls"
    target_url = f"{url}{urllib.parse.quote(payload)}"
    response = requests.get(target_url)
    if "bin" in response.text or "usr" in response.text:
        return True
    return False

# Function to perform Directory Traversal test
def test_directory_traversal(url):
    payload = "../../../../etc/passwd"
    target_url = f"{url}{urllib.parse.quote(payload)}"
    response = requests.get(target_url)
    if "root:" in response.text:
        return True
    return False

# Function to check for Broken Access Control
def test_broken_access_control(url):
    response = requests.get(url)
    if "unauthorized" in response.text.lower() or response.status_code == 403:
        return True
    return False

# Function to check for Cryptographic Failures
def test_cryptographic_failures(url):
    response = requests.get(url)
    if "http:" in response.url:
        return True
    return False

# Function to check for Insecure Design
def test_insecure_design(url):
    # Placeholder for manual review
    return False

# Function to check for Security Misconfiguration
def test_security_misconfiguration(url):
    response = requests.get(url)
    headers = response.headers
    if "X-Frame-Options" not in headers or "X-Content-Type-Options" not in headers:
        return True
    return False

# Function to check for Vulnerable and Outdated Components
def test_vulnerable_and_outdated_components(url):
    # Placeholder for manual review
    return False

# Function to check for Identification and Authentication Failures
def test_identification_and_authentication_failures(url):
    # Placeholder for manual review
    return False

# Function to check for Software and Data Integrity Failures
def test_software_and_data_integrity_failures(url):
    # Placeholder for manual review
    return False

# Function to check for Security Logging and Monitoring Failures
def test_security_logging_and_monitoring_failures(url):
    # Placeholder for manual review
    return False

# Function to check for Server-Side Request Forgery (SSRF)
def test_ssrf(url):
    payload = "http://localhost:8000"
    target_url = f"{url}{urllib.parse.quote(payload)}"
    response = requests.get(target_url)
    if "localhost" in response.text:
        return True
    return False

# Function to check CSRF token presence
def check_csrf_token(forms):
    results = []
    for form in forms:
        inputs = form.find_all("input")
        has_token = False
        for input in inputs:
            if input.get("name") and "csrf_token" in input.get("name").lower():
                has_token = True
                break
        results.append(has_token)
    return results

# Function to extract all forms from the HTML
def get_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

# Function to submit forms with malicious payloads
def test_forms(url, forms, payload):
    results = []
    for form in forms:
        action = form.get("action")
        method = form.get("method")
        form_url = urllib.parse.urljoin(url, action)
        
        inputs = form.find_all("input")
        data = {}
        for input in inputs:
            name = input.get("name")
            if input.get("type") in ["text", "search"]:
                data[name] = payload
            else:
                data[name] = input.get("value", "")
        
        if method and method.lower() == "post":
            response = requests.post(form_url, data=data)
        else:
            response = requests.get(form_url, params=data)
        
        if payload in response.text:
            results.append((form_url, True))
        else:
            results.append((form_url, False))
    
    return results

# Function to run all tests
def run_tests(url, result_text):
    result_text.delete(1.0, tk.END)
    if not url.startswith("http"):
        url = "http://" + url

    show_scanning_message()  # Show scanning message before running tests

    #result_text.insert(tk.END, "[*] Testing for SQL Injection...\n")
    if test_sql_injection(url):
        result_text.insert(tk.END, "[✓] SQL Injection vulnerability found!\n")
    else:
        result_text.insert(tk.END, "[x] No SQL Injection vulnerability found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for XSS...\n")
    if test_xss(url):
        result_text.insert(tk.END, "[✓] XSS vulnerability found!\n")
    else:
        result_text.insert(tk.END, "[x] No XSS vulnerability found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Command Injection...\n")
    if test_command_injection(url):
        result_text.insert(tk.END, "[✓] Command Injection vulnerability found!\n")
    else:
        result_text.insert(tk.END, "[x] No Command Injection vulnerability found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Directory Traversal...\n")
    if test_directory_traversal(url):
        result_text.insert(tk.END, "[✓] Directory Traversal vulnerability found!\n")
    else:
        result_text.insert(tk.END, "[x] No Directory Traversal vulnerability found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Broken Access Control...\n")
    if test_broken_access_control(url):
        result_text.insert(tk.END, "[✓] Broken Access Control vulnerability found!\n")
    else:
        result_text.insert(tk.END, "[x] No Broken Access Control vulnerability found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Cryptographic Failures...\n")
    if test_cryptographic_failures(url):
        result_text.insert(tk.END, "[✓] Cryptographic Failures found!\n")
    else:
        result_text.insert(tk.END, "[x] No Cryptographic Failures found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Insecure Design...\n")
    if test_insecure_design(url):
        result_text.insert(tk.END, "[✓] Insecure Design vulnerability found!\n")
    else:
        result_text.insert(tk.END, "[x] No Insecure Design vulnerability found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Security Misconfiguration...\n")
    if test_security_misconfiguration(url):
        result_text.insert(tk.END, "[✓] Security Misconfiguration found!\n")
    else:
        result_text.insert(tk.END, "[x] No Security Misconfiguration found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Vulnerable and Outdated Components...\n")
    if test_vulnerable_and_outdated_components(url):
        result_text.insert(tk.END, "[✓] Vulnerable and Outdated Components found!\n")
    else:
        result_text.insert(tk.END, "[x] No Vulnerable and Outdated Components found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Identification and Authentication Failures...\n")
    if test_identification_and_authentication_failures(url):
        result_text.insert(tk.END, "[✓] Identification and Authentication Failures found!\n")
    else:
        result_text.insert(tk.END, "[x] No Identification and Authentication Failures found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Software and Data Integrity Failures...\n")
    if test_software_and_data_integrity_failures(url):
        result_text.insert(tk.END, "[✓] Software and Data Integrity Failures found!\n")
    else:
        result_text.insert(tk.END, "[x] No Software and Data Integrity Failures found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for Security Logging and Monitoring Failures...\n")
    if test_security_logging_and_monitoring_failures(url):
        result_text.insert(tk.END, "[✓] Security Logging and Monitoring Failures found!\n")
    else:
        result_text.insert(tk.END, "[x] No Security Logging and Monitoring Failures found.\n")
    
    #result_text.insert(tk.END, "[*] Testing for SSRF...\n")
    if test_ssrf(url):
        result_text.insert(tk.END, "[✓] SSRF vulnerability found!\n")
    else:
        result_text.insert(tk.END, "[x] No SSRF vulnerability found.\n")
    
    #result_text.insert(tk.END, "[*] Extracting forms and testing for XSS...\n")
    forms = get_forms(url)
    if forms:
        results = test_forms(url, forms, "<script>alert('XSS')</script>")
        for result in results:
            if result[1]:
                result_text.insert(tk.END, f"[✓] XSS vulnerability found in form at {result[0]}\n")
            else:
                result_text.insert(tk.END, f"[x] No XSS vulnerability found in form at {result[0]}\n")
        
        result_text.insert(tk.END, "[*] Checking forms for CSRF tokens...\n")
        csrf_results = check_csrf_token(forms)
        for i, result in enumerate(csrf_results):
            if not result:
                result_text.insert(tk.END, f"[!] Form {i+1} is missing CSRF token!\n")
            else:
                result_text.insert(tk.END, f"[*] Form {i+1} has CSRF token.\n")
    else:
        result_text.insert(tk.END, "[x] No forms found on the page.\n")

# GUI Setup
app = tk.Tk()
app.geometry("600x500")
app.title(" Web Vulnerability Scanner")

tk.Label(app, text="Enter URL to Scan:").pack(pady=10)
url_entry = tk.Entry(app, width=50)
url_entry.pack(pady=10)

tk.Label(app, text="Example: https://www.example.com/").pack(pady=10)


# Command to run scan, now calls the function to show scanning message
scan_button = tk.Button(app, text="Run Scan", command=lambda: run_tests(url_entry.get(), result_text))
scan_button.pack(pady=10)

result_text = tk.Text(app, width=90, height=15)
result_text.pack(pady=10)

# Contact info
tk.Label(app, text="Email Me : vickymac1001@proton.me").pack(pady=10)

app.mainloop()
