#!/usr/bin/env python3
# ParrotSec Domain Checker - Python 3 / PyQt6
# Checks DNS, HTTP/HTTPS, TLS certificate, and optional WHOIS information.
from pathlib import Path
import sys
import socket
import ssl
import subprocess
import shutil
import csv
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QGroupBox, QGridLayout,
    QFileDialog, QMessageBox, QProgressBar, QFrame
)

APP_NAME = "ParrotSec Domain Checker"
ACCENT = "#00E5D0"
BG = "#101416"
PANEL = "#191f22"
TEXT = "#e6eeee"
MUTED = "#9aabab"
RED = "#ff5b68"
GREEN = "#57e389"
YELLOW = "#ffd166"


def clean_domain(value):
    value = value.strip()
    if not value:
        raise ValueError("Lütfen bir alan adı girin.")
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].split(":")[0].strip().rstrip(".")
    if not value or "." not in value or any(ch.isspace() for ch in value):
        raise ValueError("Geçerli bir alan adı girin. Örnek: ls.com.tr")
    return value.encode("idna").decode("ascii").lower()


class DomainWorker(QThread):
    progress = pyqtSignal(str)
    finished_result = pyqtSignal(str, str)

    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    def run(self):
        d = self.domain
        lines = []
        summary = []

        def section(title):
            lines.append("\n" + "=" * 58)
            lines.append(title)
            lines.append("=" * 58)

        def add(label, value):
            lines.append(f"{label:<24} {value}")

        # DNS
        self.progress.emit("DNS kayıtları kontrol ediliyor…")
        section("1. DNS KONTROLÜ")
        try:
            infos = socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)
            ips = sorted({item[4][0] for item in infos})
            add("IP adresleri:", ", ".join(ips) if ips else "Bulunamadı")
            summary.append("DNS: Çözümlendi" if ips else "DNS: IP bulunamadı")
        except Exception as e:
            add("IP adresleri:", f"HATA — {e}")
            summary.append("DNS: Çözümleme başarısız")

        try:
            add("Canonical name:", socket.getfqdn(d))
        except Exception as e:
            add("Canonical name:", f"Bulunamadı ({e})")

        try:
            import dns.resolver  # type: ignore
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 4
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
                try:
                    answers = resolver.resolve(d, rtype, raise_on_no_answer=False)
                    values = [str(x).strip('"') for x in answers] if answers.rrset else []
                    add(f"{rtype} kayıtları:", "; ".join(values) if values else "Kayıt yok")
                except Exception as e:
                    add(f"{rtype} kayıtları:", f"Yanıt yok / sorgulanamadı ({type(e).__name__})")
        except ImportError:
            add("Ek DNS kayıtları:", "dnspython kurulu değil (MX/NS/TXT/CNAME için)")
            add("Kurulum:", "python3 -m pip install dnspython")

        # HTTP / HTTPS
        self.progress.emit("HTTP ve HTTPS erişimi test ediliyor…")
        section("2. WEB ERİŞİMİ")
        for scheme in ("https", "http"):
            url = f"{scheme}://{d}"
            try:
                req = Request(url, headers={"User-Agent": "ParrotSec-Domain-Checker/1.0"})
                start = datetime.now()
                try:
                    with urlopen(req, timeout=8) as resp:
                        elapsed = (datetime.now() - start).total_seconds() * 1000
                        status = getattr(resp, "status", "Bilinmiyor")
                        final_url = resp.geturl()
                        add(f"{scheme.upper()}:", f"HTTP {status} | {elapsed:.0f} ms | {final_url}")
                        summary.append(f"{scheme.upper()}: HTTP {status}")
                except HTTPError as e:
                    elapsed = (datetime.now() - start).total_seconds() * 1000
                    add(f"{scheme.upper()}:", f"HTTP {e.code} | {elapsed:.0f} ms (sunucu yanıt verdi)")
                    summary.append(f"{scheme.upper()}: HTTP {e.code}")
            except Exception as e:
                add(f"{scheme.upper()}:", f"Erişilemedi — {type(e).__name__}: {e}")
                summary.append(f"{scheme.upper()}: Erişim hatası")

        # TLS certificate
        self.progress.emit("SSL/TLS sertifikası inceleniyor…")
        section("3. SSL / TLS SERTİFİKASI")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((d, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=d) as tls:
                    cert = tls.getpeercert()
                    add("TLS sürümü:", tls.version() or "Bilinmiyor")
                    add("Şifre paketi:", tls.cipher()[0] if tls.cipher() else "Bilinmiyor")
                    add("Sertifika sahibi:", ", ".join(f"{k}={v}" for group in cert.get("subject", ()) for k, v in group))
                    add("Veren kurum:", ", ".join(f"{k}={v}" for group in cert.get("issuer", ()) for k, v in group))
                    expiry = cert.get("notAfter")
                    if expiry:
                        exp_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days = (exp_dt - now).days
                        add("Bitiş tarihi (UTC):", exp_dt.strftime("%Y-%m-%d %H:%M:%S"))
                        add("Kalan süre:", f"{days} gün" if days >= 0 else f"SÜRESİ DOLMUŞ ({abs(days)} gün önce)")
                    else:
                        add("Sertifika bitişi:", "Bilgi alınamadı")
                    summary.append("SSL: Sertifika doğrulandı")
        except Exception as e:
            add("SSL kontrolü:", f"Başarısız — {type(e).__name__}: {e}")
            summary.append("SSL: Kontrol başarısız")

        # WHOIS
        self.progress.emit("WHOIS bilgisi aranıyor…")
        section("4. WHOIS / ALAN ADI KAYDI")
        whois_bin = shutil.which("whois")
        if whois_bin:
            try:
                result = subprocess.run(
                    [whois_bin, d], capture_output=True, text=True, timeout=15
                )
                output = (result.stdout or result.stderr).strip()
                if output:
                    lines.append(output[:12000])
                    summary.append("WHOIS: Sonuç alındı")
                else:
                    add("WHOIS:", "Sunucudan bilgi gelmedi")
            except Exception as e:
                add("WHOIS:", f"Sorgu başarısız — {e}")
        else:
            add("WHOIS:", "whois komutu kurulu değil")
            add("Kurulum (Debian/Parrot):", "sudo apt install whois")

        section("5. ÖZET")
        lines.extend(summary or ["Kontrol tamamlandı."])
        lines.append("\nNot: Sonuçlar mevcut ağ bağlantısına, DNS sağlayıcısına ve uzak sunuculara bağlıdır.")
        self.finished_result.emit("\n".join(lines), "\n".join(summary))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(920, 760)
        logo_path = Path(__file__).resolve().with_name("parrot-security-512px.png")
        if logo_path.is_file():
            self.setWindowIcon(QIcon(str(logo_path)))
        self.setMinimumSize(720, 600)
        self.last_report = ""

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 18, 20, 16)
        root.setSpacing(12)

        header = QHBoxLayout()
        logo = QLabel()
        logo.setObjectName("logo")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setFixedSize(58, 58)
        logo_path = Path(__file__).resolve().with_name("parrot-security-512px.png")
        if logo_path.is_file():
            logo.setPixmap(QPixmap(str(logo_path)).scaled(52, 52, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        else:
            logo.setText("PS")
        title_col = QVBoxLayout()
        title = QLabel("ParrotSec Domain Checker")
        title.setObjectName("title")
        subtitle = QLabel("DNS  •  WHOIS  •  HTTP/HTTPS  •  SSL/TLS")
        subtitle.setObjectName("subtitle")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header.addWidget(logo)
        header.addSpacing(12)
        header.addLayout(title_col)
        header.addStretch()
        badge = QLabel("NETWORK TOOLS")
        badge.setObjectName("badge")
        header.addWidget(badge, alignment=Qt.AlignmentFlag.AlignVCenter)
        root.addLayout(header)

        box = QGroupBox("Alan adı sorgula")
        box_layout = QHBoxLayout(box)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Örnek: ls.com.tr")
        self.domain_input.returnPressed.connect(self.start_check)
        self.check_btn = QPushButton("▶  SORGULA")
        self.check_btn.setObjectName("primary")
        self.check_btn.clicked.connect(self.start_check)
        box_layout.addWidget(self.domain_input, 1)
        box_layout.addWidget(self.check_btn)
        root.addWidget(box)

        status_row = QHBoxLayout()
        self.status = QLabel("Hazır — sorgulamak istediğiniz alan adını girin.")
        self.status.setObjectName("status")
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(130)
        self.progress.hide()
        status_row.addWidget(self.status, 1)
        status_row.addWidget(self.progress)
        root.addLayout(status_row)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.output.setPlaceholderText("Sorgulama sonuçları burada görüntülenecek…")
        self.output.setFont(QFont("Monospace", 10))
        root.addWidget(self.output, 1)

        footer = QHBoxLayout()
        self.save_btn = QPushButton("Raporu TXT Kaydet")
        self.save_btn.clicked.connect(self.save_txt)
        self.csv_btn = QPushButton("Özeti CSV Kaydet")
        self.csv_btn.clicked.connect(self.save_csv)
        clear_btn = QPushButton("Temizle")
        clear_btn.clicked.connect(self.clear)
        footer.addWidget(self.save_btn)
        footer.addWidget(self.csv_btn)
        footer.addStretch()
        footer.addWidget(clear_btn)
        root.addLayout(footer)

        self.setStyleSheet(f"""
            QWidget {{ background: {BG}; color: {TEXT}; font-family: 'Noto Sans', 'DejaVu Sans'; font-size: 10pt; }}
            QLabel#logo {{ background: #071c1b; border: 2px solid {ACCENT}; border-radius: 12px; }}
            QLabel#title {{ color: {ACCENT}; font-size: 19pt; font-weight: 700; }}
            QLabel#subtitle {{ color: {MUTED}; font-size: 9pt; }}
            QLabel#badge {{ color: {ACCENT}; border: 1px solid #28635e; border-radius: 6px; padding: 7px 10px; font-size: 8pt; font-weight: bold; }}
            QLabel#status {{ color: {MUTED}; }}
            QGroupBox {{ border: 1px solid #354144; border-radius: 9px; margin-top: 10px; padding: 12px; font-weight: bold; color: {ACCENT}; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 5px; }}
            QLineEdit {{ background: {PANEL}; border: 1px solid #455356; border-radius: 6px; padding: 11px; selection-background-color: {ACCENT}; color: {TEXT}; }}
            QLineEdit:focus {{ border: 1px solid {ACCENT}; }}
            QPushButton {{ background: #252e31; border: 1px solid #455356; border-radius: 6px; padding: 9px 13px; color: {TEXT}; }}
            QPushButton:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
            QPushButton#primary {{ background: #063a36; border: 1px solid {ACCENT}; color: {ACCENT}; font-weight: bold; padding: 11px 18px; }}
            QTextEdit {{ background: #0b0f11; border: 1px solid #354144; border-radius: 8px; padding: 12px; color: #c9f7ed; selection-background-color: #176b61; }}
            QProgressBar {{ border: 1px solid #354144; border-radius: 3px; height: 7px; text-align: center; }}
            QProgressBar::chunk {{ background: {ACCENT}; }}
        """)

    def start_check(self):
        try:
            domain = clean_domain(self.domain_input.text())
        except ValueError as e:
            QMessageBox.warning(self, "Alan adı hatası", str(e))
            return
        self.domain_input.setText(domain)
        self.output.setPlainText(f"{domain} için kontroller başlatılıyor…\n\nLütfen bekleyin.")
        self.status.setText(f"{domain} kontrol ediliyor…")
        self.progress.show()
        self.check_btn.setEnabled(False)
        self.worker = DomainWorker(domain)
        self.worker.progress.connect(self.status.setText)
        self.worker.finished_result.connect(self.show_result)
        self.worker.start()

    def show_result(self, report, summary):
        self.last_report = report
        self.output.setPlainText(report)
        self.progress.hide()
        self.check_btn.setEnabled(True)
        self.status.setText("Kontrol tamamlandı. Sonuçları inceleyebilir veya kaydedebilirsiniz.")

    def save_txt(self):
        if not self.last_report:
            QMessageBox.information(self, "Bilgi", "Önce bir alan adı sorgulayın.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Raporu kaydet", "domain-report.txt", "Text files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.last_report)
            self.status.setText(f"Rapor kaydedildi: {path}")

    def save_csv(self):
        if not self.last_report:
            QMessageBox.information(self, "Bilgi", "Önce bir alan adı sorgulayın.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Özeti kaydet", "domain-summary.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["Domain", "Summary"])
                summary = self.last_report.split("5. ÖZET", 1)[-1].strip()
                writer.writerow([self.domain_input.text(), summary.replace("\n", " | ")])
            self.status.setText(f"CSV kaydedildi: {path}")

    def clear(self):
        self.output.clear()
        self.domain_input.clear()
        self.last_report = ""
        self.status.setText("Hazır — sorgulamak istediğiniz alan adını girin.")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
