import tkinter as tk
from tkinter import filedialog, Text, messagebox, Toplevel
from tkinter import *
import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import OpenSSL
import whois
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import math

# Initialize suspicion variables
suspicion_meter = 0.0
suspicion_pool = 0.0
ca_info = None 
domain_creation_date = None

def url_exists(url):
    """Check if the URL exists."""
    try:
        response = requests.head(url, allow_redirects=True)
        if response.status_code in [200, 302]:
            return True
        else:
            return False
    except Exception as e:
        messagebox.showerror("Error", f"Request Exception: {e}")
        return False

def match_hostname(cert_cn, hostname):
    """Match certificate's CN with the hostname."""
    if cert_cn.startswith("*."):
        base_domain = cert_cn[2:]
        return hostname.endswith(base_domain)
    else:
        return cert_cn == hostname

def get_crl_distribution_points(cert):
    """Fetch CRL distribution points from the certificate."""
    crl_distribution_points = []
    try:
        for ext in cert.extensions:
            if ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                crl_distribution_points = [str(dp.full_name[0].value) for dp in ext.value]
                break
    except Exception as e:
        messagebox.showerror("Error", f"Error getting CRL distribution points: {e}")
    return crl_distribution_points

def check_crl(cert):
    """Check if the certificate is revoked using CRL."""
    crl_urls = get_crl_distribution_points(cert)
    if not crl_urls:
        return True  # If no CRL, assume not revoked.

    for url in crl_urls:
        try:
            response = requests.get(url)
            response.raise_for_status()
            crl_data = response.content
            try:
                crl = x509.load_pem_x509_crl(crl_data, default_backend())
            except ValueError:
                crl = x509.load_der_x509_crl(crl_data, default_backend())
            for revoked_cert in crl:
                if revoked_cert.serial_number == cert.serial_number:
                    messagebox.showerror("CRL Check", f"Certificate is revoked according to CRL at {url}.")
                    return False
        except Exception as e:
            messagebox.showerror("Error", f"Error fetching or parsing CRL from {url}: {e}")
    return True

def get_ssl_certificate(url, port=443):
    """Retrieve SSL certificate from the server."""
    global ca_info
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject['commonName']
        issued_by = issuer['commonName']
        valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        ca_info = {
            'issued_to': issued_to,
            'issued_by': issued_by,
            'valid_from': valid_from,
            'valid_until': valid_until,
        }
        return ca_info
    except Exception as e:
        messagebox.showerror("Error", f"Failed to retrieve SSL certificate: {e}")
        return None

def verify_ssl_certificate(url):
    """Verify the SSL certificate."""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

        cert2 = load_der_x509_certificate(cert, default_backend())
        cert_subject = {k.decode('utf-8'): v.decode('utf-8') for k, v in x509_cert.get_subject().get_components()}
        issued_to = cert_subject.get('CN', 'Unknown')
        valid_from = datetime.strptime(x509_cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        valid_until = datetime.strptime(x509_cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')

        if valid_until < datetime.utcnow():
            messagebox.showinfo("SSL Status", f"Certificate for {issued_to} has expired.")
            return False
        if not match_hostname(issued_to, hostname):
            messagebox.showinfo("SSL Status", f"Certificate's CN '{issued_to}' does not match hostname '{hostname}'.")
            return False
        if not check_crl(cert2):
            return False
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Failed to verify SSL certificate: {e}")
        return False

def get_domain_age(url):
    """Check domain age using WHOIS."""
    global suspicion_pool, suspicion_meter, domain_creation_date
    suspicion_pool += 10
    domain_name = urlparse(url).hostname
    try:
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        domain_creation_date = creation_date 
        domain_age = datetime.now() - creation_date
        if domain_age.days < 1:
            suspicion_meter += 0
        else:
            suspicion_meter += math.log(domain_age.days, 365) * 10
        return domain_age.days
    except Exception as e:
        messagebox.showerror("Error", f"Error retrieving domain information: {e}")
        return None

def check_url():
    global suspicion_meter, suspicion_pool
    suspicion_meter = 0
    suspicion_pool = 0

    url = text_box.get("1.0", tk.END).strip()

    if url_exists(url):
        ca_info = get_ssl_certificate(url)
        if ca_info:
            suspicion_pool += 10
            if verify_ssl_certificate(url):
                suspicion_meter += 10
            domain_age = get_domain_age(url)
            if domain_age:
                if (suspicion_meter / suspicion_pool) < 1:
                    result.set(f"CAUTION! This site may be phishing.\nSuspicion Score: {suspicion_pool / suspicion_meter:.4f}")
                else:
                    result.set(f"The site is likely safe.\nSuspicion Score: {suspicion_pool / suspicion_meter:.4f}")
    else:
        result.set("The URL does not exist.")

def show_details():
    global ca_info, domain_creation_date
    if not ca_info or not domain_creation_date:
        messagebox.showinfo("No Data", "Please check a URL first to retrieve the details.")
        return

    details_window = Toplevel(app)
    details_window.title("Additional Details")
    icon = PhotoImage(file="D:/vscode files/Rubyworks/pish/phish.png")
    details_window.iconphoto(False, icon)
    details_window.geometry("400x300")

    details_text = (
        f"Issued To: {ca_info['issued_to']}\n"
        f"Issued By: {ca_info['issued_by']}\n"
        f"Valid From: {ca_info['valid_from']}\n"
        f"Valid Until: {ca_info['valid_until']}\n"
        f"Domain Creation Date: {domain_creation_date}\n"
        f"Domain Age: {(datetime.now() - domain_creation_date).days} days"
    )

    global details_label
    details_label = Label(details_window, text=details_text, justify=LEFT, font=('arial', 12))
    details_label.pack(padx=10, pady=10)

app = tk.Tk()
app.title('Phishing Site Detector')
icon = PhotoImage(file="D:/vscode files/Rubyworks/pish/phish.png")
app.iconphoto(False, icon)
app.geometry('400x400')

label = Label(app, text="Enter URL", font=('arial', 15))
label.pack(pady=10)

text_box = Text(app, height=2, width=50)
text_box.pack(pady=10)

result = StringVar()
result_label = Label(app, textvariable=result, wraplength=300, font=('arial', 10))
result_label.pack(pady=20)

check_button = Button(app, text="Check URL", command=check_url, padx=10, pady=5)
check_button.pack(pady=10)

details_button = Button(app, text="Additional Details", command=show_details, padx=10, pady=5)
details_button.pack(pady=20)

label2 = Label(app, text="*Note: suspiction score between (0,1) is considered safe.", font=('arial', 10))
label2.pack(pady=10)

app.mainloop()
