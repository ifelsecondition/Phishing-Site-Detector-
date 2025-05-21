from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame
)
from PyQt6.QtWidgets import QFileDialog

from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt
import sys
import datetime
from main import (browser_running, get_browser_url, get_ip_from_url,
                            get_country_from_url, advanced_url_analysis,
                            detect_suspicious_elements, check_safe_browsing)

from certificate_checker import get_ssl_info
from certificate_checker import calculate_threat_level
from main import malicious_ip
from PyQt6.QtWidgets import QApplication, QPushButton, QMessageBox
Get_url = get_browser_url() #gives the url

Get_domain = advanced_url_analysis(Get_url) #only provide domins subdomain and full domain
 # getiing the domains
domain = Get_domain['domain']


Get_country = get_country_from_url(Get_url) # gives country name
Get_ip = get_ip_from_url(Get_url) # provides the ip

Get_ssl = get_ssl_info(domain['full_domain'])

issuer = Get_ssl.get('issuer', '') if Get_ssl else ''
Valid_from = Get_ssl.get('valid_from', '') if Get_ssl else ''
Valid_to = Get_ssl.get('valid_to', '') if Get_ssl else ''
remaining_days = Get_ssl.get('remaining_days', 0) if Get_ssl else 0
sans = Get_ssl.get('SANs', []) if Get_ssl else []


#threat lvls

threat, reason = calculate_threat_level(Get_ssl,Get_ip, malicious_ip)



def generate_textfile(Get_url, Get_ip, Get_country, issuer, Valid_from, Valid_to, remaining_days, threat, reason):
    options = QFileDialog.Option.DontUseNativeDialog
    file_name, _ = QFileDialog.getSaveFileName(
        None,
        "Save File",
        "",
        "Text Files (*.txt);;All Files (*)",
        options=options
    )
    if file_name:
        with open(file_name, "w",  encoding="utf-8") as file:
            file.write("Network Analysis Report\n")
            file.write("-----------------------------------\n")
            file.write(f"URL: {Get_url}\n")
            file.write(f"IP: {Get_ip}\n")
            file.write(f"Country: {Get_country}\n")
            file.write(f"Issuer: {issuer}\n")
            file.write(f"Valid From: {Valid_from}\n")
            file.write(f"Valid To: {Valid_to}\n")
            file.write(f"Remaining Days: {remaining_days}\n")
            file.write(f"Threat: {threat}\n")
            file.write(f"Reason: {reason}\n")


def url_blocked(url):
    
    print(url)
    show_block_alert(url)


def show_block_alert(url):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Information)
    msg.setWindowTitle("🚫 Site Blocked")
    msg.setText("The website has been successfully blocked!")
    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
    msg.exec()

class PhishingDashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing Intelligence Dashboard")
        self.setGeometry(100, 100, 1200, 450)
        self.setStyleSheet("background-color: #111727; color: white; font-family: 'Poppins';")
        
        self.initUI()
        
    def initUI(self):
        main_layout = QVBoxLayout(self)

        # --- Header Section ---
        header_layout = QHBoxLayout()
        
        title = QLabel("Phishing Intelligence Dashboard")
        title.setFont(QFont("Poppins", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: white")
        
       
       
       
        block = QPushButton("Block Site")
        block.setStyleSheet("""
            QPushButton {
        background-color: red;
        color: white;
        border-radius: 200px;
        padding: 10px 20px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: qlineargradient(
    spread:pad, 
    x1:0, y1:0, x2:1, y2:0, 
    stop:0 #EF4444, 
    stop:1 #DC2626   
);
    }
""")
       
       
       
       
       
       
        
        download_button = QPushButton("Download Report")
        download_button.setStyleSheet("""
            QPushButton {
        background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #3B82F6, stop:1 #8B5CF6);
        color: white;
        border-radius: 200px;
        padding: 10px 20px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #2563EB, stop:1 #7C3AED);
    }
""")

        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(download_button)
        header_layout.addWidget(block)
        block.clicked.connect(lambda: url_blocked(Get_url))
        download_button.clicked.connect(lambda: generate_textfile(Get_url, Get_ip, Get_country, issuer, Valid_from, Valid_to, remaining_days, threat, reason) )
        main_layout.addLayout(header_layout)
        
        # --- Main Content Section ---
        content_layout = QHBoxLayout()

        # --- Left Side (Graph) ---
        graph_frame = QFrame()
        graph_frame.setStyleSheet("""
            background-color: rgba(29, 41, 55, 0.8);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
        """)
        graph_frame.setFixedHeight(400)
        
        graph_layout = QVBoxLayout(graph_frame)
        graph_title = QLabel("Network Certification Analysis")
        graph_title.setFont(QFont("Poppins", 14))
        graph_title.setStyleSheet("color: white;")
        
        ssl_placeholder = QLabel("SSL Details")
        ssl_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ssl_placeholder.setStyleSheet("color: gray; font-size:20px")
        
        
        ssl_info_text1 = QLabel(f"Domain: {domain['main_domain']}")
        ssl_info_text1.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text1.setFont(QFont("Poppins", 10))
        ssl_info_text1.setStyleSheet("color: white; padding: 5px;")
        
        ssl_info_text2 = QLabel(f"Url: {Get_url}")
        ssl_info_text2.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text2.setFont(QFont("Poppins", 10))
        ssl_info_text2.setStyleSheet("color: white; padding: 5px;")
        
        ssl_info_text3 = QLabel(f"Issuer: {issuer} ")
        ssl_info_text3.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text3.setFont(QFont("Poppins", 10))
        ssl_info_text3.setStyleSheet("color: white; padding: 5px;")
        
        ssl_info_text4 = QLabel(f"Valid From: {Valid_from}")
        ssl_info_text4.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text4.setFont(QFont("Poppins", 10))
        ssl_info_text4.setStyleSheet("color: white; padding: 5px;")
        
        ssl_info_text5 = QLabel(f"Valid Until: {Valid_to}")
        ssl_info_text5.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text5.setFont(QFont("Poppins", 10))
        ssl_info_text5.setStyleSheet("color: white; padding: 5px;")
        
        ssl_info_text6 = QLabel(f"Days Lefts: {remaining_days}")
        ssl_info_text6.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text6.setFont(QFont("Poppins", 10))
        ssl_info_text6.setStyleSheet("color: white; padding: 5px;")
        
        ssl_info_text7 = QLabel(f"SANs: {sans}")
        ssl_info_text7.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text7.setFont(QFont("Poppins", 10))
        ssl_info_text7.setStyleSheet("color: white; padding: 5px; ")
        ssl_info_text7.setWordWrap(True)
        
        ssl_info_text8 = QLabel(f"Threat Level: {threat}")
        ssl_info_text8.setAlignment(Qt.AlignmentFlag.AlignLeft) 
        ssl_info_text8.setFont(QFont("Poppins", 10))
        ssl_info_text8.setStyleSheet("color: white; padding: 5px;")

        
        
        
        graph_layout.addWidget(graph_title)
        graph_layout.addWidget(ssl_placeholder)
        graph_layout.addWidget(ssl_info_text1)
        graph_layout.addWidget(ssl_info_text2)
        graph_layout.addWidget(ssl_info_text3)
        graph_layout.addWidget(ssl_info_text4)
        graph_layout.addWidget(ssl_info_text5)
        graph_layout.addWidget(ssl_info_text6)
        graph_layout.addWidget(ssl_info_text7)
        graph_layout.addWidget(ssl_info_text8)
        graph_layout.addStretch()
        
        # --- Right Side (Threat Intelligence) ---
        details_frame = QFrame()
        details_frame.setStyleSheet("""
            background-color: rgba(29, 41, 55, 0.8);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
        """)
        details_frame.setFixedWidth(350)
        
        details_layout = QVBoxLayout(details_frame)
        details_title = QLabel("URL Details")
        details_title.setFont(QFont("Poppins", 20))
        
       
        
        
        domain_label = QLabel(f"Full Domain Name: {domain['full_domain']} ")
        ip_label = QLabel(f"IP Address: {Get_ip}")
        location_label = QLabel(f"Location: {Get_country}")
        threats = QLabel(f"Threat: {threat}")
        reasons = QLabel(f"Reason: {reason}")
        
        for lbl in [domain_label, ip_label, location_label]:
            lbl.setStyleSheet("color: white; font-size: 14px; margin-top: 10px;")
        
        details_layout.addWidget(details_title)
        details_layout.addWidget(domain_label)
        details_layout.addWidget(ip_label)
        details_layout.addWidget(location_label)
        details_layout.addWidget(threats)
        details_layout.addWidget(reasons)
        details_layout.addStretch()
        
        content_layout.addWidget(graph_frame)
        content_layout.addWidget(details_frame)
        
        main_layout.addLayout(content_layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PhishingDashboard()
    window.show()
    sys.exit(app.exec())
