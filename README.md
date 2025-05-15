# flasher
A PyQt-based desktop application to digitally sign firmware (.bin) files using RSA keys, verify file hashes (SHA-256), and optionally upload signed binaries. Built for secure OTA updates and embedded system pipelines.

# 🔐 Firmware Signing & Verification GUI – PyQt App

This is a PyQt5 desktop application for **securely signing firmware binaries** using **RSA keys**, verifying the integrity via **SHA-256 hashes**, and optionally uploading the verified firmware for OTA updates.

---

## ✅ Features

- 📦 Sign `.bin` firmware files with RSA private key
- 🔐 Verify with RSA public key
- 🧮 SHA-256 hash generation and comparison
- 📤 Upload signed files (optional: via serial, HTTP, or SFTP)
- 💻 Clean, intuitive GUI with PyQt5

---

## 🧰 Technologies

| Component     | Purpose                           |
|---------------|------------------------------------|
| **PyQt5**     | Desktop GUI framework              |
| **RSA (PyCryptodome)** | Digital signature (PKI)      |
| **SHA-256**   | Hash verification of binaries      |
| **Python 3**  | Language base                      |

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/firmware_signer_gui.git
cd firmware_signer_gui

