import os
import sys
import serial
import serial.tools.list_ports
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from PyQt6.QtWidgets import (QApplication, QMainWindow, QMessageBox, 
                            QFileDialog, QProgressDialog, QInputDialog, QLineEdit)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer

# UI Loading
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UI_FILE = os.path.join(BASE_DIR, 'mainwindow.ui')

if os.path.exists(UI_FILE):
    from PyQt6.uic import loadUiType
    Ui_MainWindow, _ = loadUiType(UI_FILE)
else:
    raise FileNotFoundError(f"UI file not found at {UI_FILE}")

class FileManager:
    @staticmethod
    def get_sig_file_path(file_path):
        """Get the corresponding signature file path"""
        return f"{file_path}.sig"

    @staticmethod
    def is_file_signed(file_path):
        """Check if file has a signature"""
        return os.path.exists(FileManager.get_sig_file_path(file_path))

    @staticmethod
    def validate_file(file_path):
        """Validate file exists and is accessible"""
        if not file_path or not os.path.exists(file_path):
            return False
        return True

    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()

class SerialConnection:
    def __init__(self):
        self.serial = None
        self.is_connected = False
        self.timeout = 2  # seconds

    def connect(self, port, baud_rate):
        if self.is_connected:
            self.disconnect()
        
        try:
            self.serial = serial.Serial(
                port=port,
                baudrate=baud_rate,
                timeout=self.timeout,
                write_timeout=self.timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )
            self.is_connected = True
            
            # Test connection
            self.serial.write(b'\n\n')  # Wake-up command
            response = self.serial.read(100).decode(errors='ignore').strip()
            
            if not any(x in response.lower() for x in ['ardupilot', 'px4', 'chibios']):
                self.disconnect()
                raise serial.SerialException("Not an ArduPilot-compatible board")
                
            return True
            
        except Exception as e:
            print(f"Connection error: {e}")
            if self.serial:
                self.serial.close()
            self.is_connected = False
            return False

    def disconnect(self):
        if self.serial and self.serial.is_open:
            self.serial.close()
        self.is_connected = False
        return True

class BoardDetectionThread(QThread):
    detected = pyqtSignal(list)
    status = pyqtSignal(str)
    
    def run(self):
        """Detect ArduPilot-compatible boards"""
        boards = []
        try:
            self.status.emit("Scanning serial ports...")
            ports = serial.tools.list_ports.comports()
            
            for port in ports:
                self.status.emit(f"Checking {port.device}...")
                if self.is_ardupilot_board(port.device):
                    board_info = {
                        'port': port.device,
                        'description': port.description,
                        'manufacturer': port.manufacturer,
                        'type': self.detect_board_type(port.device)
                    }
                    boards.append(board_info)
            
            self.detected.emit(boards)
            msg = f"Found {len(boards)} ArduPilot board(s)" if boards else "No ArduPilot boards found"
            self.status.emit(msg)
            
        except Exception as e:
            self.status.emit(f"Detection error: {str(e)}")
            self.detected.emit([])
    
    def is_ardupilot_board(self, port_name):
        """Check if port has ArduPilot device"""
        try:
            serial_conn = SerialConnection()
            if serial_conn.connect(port_name, 57600):
                response = serial_conn.send_command('\n')
                serial_conn.disconnect()
                if response:
                    return any(x in response.lower() for x in ['ardupilot', 'px4', 'chibios'])
            return False
        except:
            return False
    
    def detect_board_type(self, port_name):
        """Determine board type by querying"""
        try:
            serial_conn = SerialConnection()
            if serial_conn.connect(port_name, 115200):
                response = serial_conn.send_command('version')
                serial_conn.disconnect()
                if response:
                    response = response.lower()
                    if 'pixhawk' in response:
                        return 'Pixhawk'
                    elif 'cube' in response:
                        return 'Cube'
                    elif 'fmu' in response:
                        return 'FMU'
                    return 'Generic ArduPilot'
            return 'Unknown'
        except:
            return 'Unknown'

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        
        # Initialize variables
        self.current_key = None
        self.current_cert = None
        self.serial_connection = SerialConnection()
        self.detected_boards = []
        
        # Setup UI
        self.setup_connections()
        self.update_ui_state()
        
        # Initial detection
        QTimer.singleShot(100, self.detect_boards)

    def setup_connections(self):
        """Connect UI signals"""
        # File selection buttons
        self.selectBinButton.clicked.connect(lambda: self.select_file(self.binFilePath, "bin"))
        self.selectApjButton.clicked.connect(lambda: self.select_file(self.apjFilePath, "apj"))
        self.selectFirmwareButton.clicked.connect(lambda: self.select_file(self.firmwarePath, "firmware"))
        
        # Action buttons
        self.refreshButton.clicked.connect(self.detect_boards)
        self.connectButton.clicked.connect(self.toggle_connection)
        self.loadKeyButton.clicked.connect(self.load_pfx)
        self.exportKeyButton.clicked.connect(self.export_key)
        self.signBinButton.clicked.connect(lambda: self.sign_file('bin'))
        self.signApjButton.clicked.connect(lambda: self.sign_file('apj'))
        self.verifyButton.clicked.connect(self.verify_signature)
        self.flashButton.clicked.connect(self.flash_firmware)
        
        # Baud rate setup
        self.baudRateComboBox.addItems(["9600", "19200", "38400", "57600", "115200"])
        self.baudRateComboBox.setCurrentText("115200")

    def select_file(self, line_edit, file_type):
        """Select a file with appropriate filters"""
        if file_type == "bin":
            filters = "Bin Files (*.bin);;All Files (*)"
        elif file_type == "apj":
            filters = "APJ Files (*.apj);;All Files (*)"
        else:
            filters = "Firmware Files (*.bin *.apj);;All Files (*)"
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", filters
        )
        
        if file_path:
            line_edit.setText(file_path)
            self.update_file_status(file_path)
            self.update_ui_state()

    def update_file_status(self, file_path):
        """Update UI to show file signing status"""
        if FileManager.is_file_signed(file_path):
            self.statusLabel.setText(f"{os.path.basename(file_path)} (signed)")
        else:
            self.statusLabel.setText(f"{os.path.basename(file_path)} (unsigned)")

    def verify_signature(self):
        """Verify file signature with proper handling for both signed/unsigned"""
        line_edit = self.binFilePath if self.binFilePath.text() else self.apjFilePath
        file_path = line_edit.text()
        
        if not FileManager.validate_file(file_path):
            self.show_error("Invalid File", "Please select a valid file first")
            return
            
        sig_file = FileManager.get_sig_file_path(file_path)
        file_hash = FileManager.calculate_file_hash(file_path)
        
        if not os.path.exists(sig_file):
            self.show_info(
                "Verification Result",
                f"⚠️ File is not signed\n\n"
                f"File: {os.path.basename(file_path)}\n"
                f"SHA256: {file_hash}\n\n"
                "No .sig file found for verification."
            )
            return
            
        if not self.current_cert:
            self.show_error("No Certificate", "Please load a certificate first")
            return
            
        progress = QProgressDialog("Verifying signature...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        
        try:
            # Read signature
            with open(sig_file, 'rb') as f:
                signature = f.read()
            
            # Verify signature
            self.current_cert.public_key().verify(
                signature,
                bytes.fromhex(file_hash),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.show_info(
                "Verification Result",
                f"✅ File is properly signed\n\n"
                f"File: {os.path.basename(file_path)}\n"
                f"SHA256: {file_hash}\n\n"
                "Signature matches the loaded certificate."
            )
            
        except Exception as e:
            self.show_error(
                "Verification Failed",
                f"❌ Signature is invalid\n\n"
                f"File: {os.path.basename(file_path)}\n"
                f"SHA256: {file_hash}\n\n"
                f"Error: {str(e)}\n\n"
                "Possible causes:\n"
                "- File was modified after signing\n"
                "- Signed with a different key\n"
                "- Certificate doesn't match signature"
            )
        finally:
            progress.close()

    def detect_boards(self):
        """Start board detection"""
        self.statusLabel.setText("Detecting boards...")
        self.refreshButton.setEnabled(False)
        
        self.detection_thread = BoardDetectionThread()
        self.detection_thread.detected.connect(self.on_boards_detected)
        self.detection_thread.status.connect(self.statusLabel.setText)
        self.detection_thread.finished.connect(self.detection_thread.deleteLater)
        self.detection_thread.start()
    
    def on_boards_detected(self, boards):
        """Handle detected boards"""
        self.detected_boards = boards
        self.portComboBox.clear()
        
        if boards:
            for board in boards:
                self.portComboBox.addItem(
                    f"{board['port']} - {board['type']}",
                    board['port']
                )
        self.refreshButton.setEnabled(True)
        self.update_ui_state()
    
    def toggle_connection(self):
        """Connect/disconnect from selected board"""
        if self.serial_connection.is_connected:
            if self.serial_connection.disconnect():
                self.connectButton.setText("Connect")
                self.statusLabel.setText("Disconnected")
                self.update_ui_state()
            return
        
        port = self.portComboBox.currentData()
        if not port:
            self.show_error("No Port", "Please select a port first")
            return
        
        baud_rate = int(self.baudRateComboBox.currentText())
        
        if self.serial_connection.connect(port, baud_rate):
            self.connectButton.setText("Disconnect")
            self.statusLabel.setText(f"Connected to {port} @ {baud_rate} baud")
            
            # Get board info
            response = self.serial_connection.send_command('version')
            if response:
                self.statusLabel.setText(f"{port}: {response[:100]}...")
            else:
                self.statusLabel.setText(f"Connected to {port} (no response)")
            
            self.update_ui_state()
        else:
            self.show_error("Connection Failed", f"Could not connect to {port}")

    def load_pfx(self):
        """Load PKCS#12 key file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select PFX/P12 File", "", "PFX Files (*.pfx *.p12)"
        )
        
        if not file_path:
            return
            
        password, ok = QInputDialog.getText(
            self, "PFX Password", 
            "Enter PFX password:", 
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            return
            
        progress = QProgressDialog("Loading PFX file...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setCancelButton(None)
        progress.show()
        
        try:
            with open(file_path, 'rb') as f:
                pfx_data = f.read()
            
            private_key, cert, _ = pkcs12.load_key_and_certificates(
                pfx_data,
                password.encode(),
                backend=default_backend()
            )
            
            if private_key and cert:
                self.current_key = private_key
                self.current_cert = cert
                
                subject = dict(x[0] for x in cert.subject)
                cn = subject.get('CN', 'Unknown')
                org = subject.get('O', 'Unknown Organization')
                valid_to = cert.not_valid_after.strftime('%Y-%m-%d')
                
                self.keyStatusLabel.setText(
                    f"Loaded: {cn}\n"
                    f"Organization: {org}\n"
                    f"Valid until: {valid_to}"
                )
                self.statusLabel.setText("PFX key loaded successfully")
                self.update_ui_state()
            else:
                self.show_error("PFX Load Error", "No valid key/certificate found in PFX")
                
        except Exception as e:
            self.show_error("PFX Load Error", str(e))
        finally:
            progress.close()

    def export_key(self):
        """Export the current key to PEM format"""
        if not self.current_key or not self.current_cert:
            self.show_error("No Key", "No key loaded to export")
            return
            
        default_name = "ardupilot_key_"+datetime.now().strftime("%Y%m%d")
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Key", default_name, "PEM Files (*.pem)"
        )
        
        if not file_path:
            return
            
        try:
            if not file_path.lower().endswith('.pem'):
                file_path += '.pem'
            
            with open(file_path, 'wb') as f:
                f.write(self.current_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            cert_path = os.path.splitext(file_path)[0] + '_cert.pem'
            with open(cert_path, 'wb') as f:
                f.write(self.current_cert.public_bytes(
                    serialization.Encoding.PEM
                ))
            
            self.show_info(
                "Export Successful",
                f"Private key exported to:\n{file_path}\n\n"
                f"Certificate exported to:\n{cert_path}"
            )
            self.statusLabel.setText("Keys exported successfully")
            
        except Exception as e:
            self.show_error("Export Error", str(e))

    def sign_file(self, file_type):
        """Sign the selected file"""
        line_edit = self.binFilePath if file_type == 'bin' else self.apjFilePath
        file_path = line_edit.text()
        
        if not FileManager.validate_file(file_path):
            return
            
        if not self.current_key:
            self.show_error("No Key", "Please load a key first")
            return
            
        progress = QProgressDialog(
            f"Signing {os.path.basename(file_path)}...", 
            "Cancel", 0, 100, self
        )
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        
        try:
            sha256 = hashlib.sha256()
            total_size = os.path.getsize(file_path)
            chunk_size = 4096
            bytes_read = 0
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    sha256.update(chunk)
                    bytes_read += len(chunk)
                    progress.setValue(int(bytes_read / total_size * 100))
                    if progress.wasCanceled():
                        break
            
            if progress.wasCanceled():
                self.statusLabel.setText("Signing cancelled")
                return
            
            signature = self.current_key.sign(
                sha256.digest(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            sig_file = FileManager.get_sig_file_path(file_path)
            with open(sig_file, 'wb') as f:
                f.write(signature)
            
            self.show_info(
                "Signing Complete",
                f"File: {os.path.basename(file_path)}\n"
                f"SHA256: {sha256.hexdigest()}\n\n"
                f"Signature saved to:\n{os.path.basename(sig_file)}"
            )
            self.statusLabel.setText("File signed successfully")
            self.update_file_status(file_path)
            
        except Exception as e:
            self.show_error("Signing Error", str(e))
        finally:
            progress.close()
    
    def flash_firmware(self):
        """Flash firmware with signature verification"""
        port = self.portComboBox.currentData()
        file_path = self.firmwarePath.text()
        
        if not port:
            self.show_error("No Board", "Please select a board first")
            return
            
        if not FileManager.validate_file(file_path):
            return
            
        # Check signature
        sig_file = FileManager.get_sig_file_path(file_path)
        if os.path.exists(sig_file):
            try:
                with open(sig_file, 'rb') as f:
                    signature = f.read()
                
                file_hash = FileManager.calculate_file_hash(file_path)
                
                self.current_cert.public_key().verify(
                    bytes.fromhex(signature.hex()),
                    bytes.fromhex(file_hash),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                self.statusLabel.setText("Verified signed firmware")
                
            except Exception as e:
                reply = QMessageBox.question(
                    self, "Invalid Signature",
                    f"Firmware signature is invalid:\n{str(e)}\n\nFlash anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
        else:
            reply = QMessageBox.question(
                self, "Unsigned Firmware",
                "This firmware isn't signed. Flash anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Flash process
        progress = QProgressDialog(
            f"Flashing to {port}...", 
            "Cancel", 0, 100, self
        )
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        
        try:
            # Simulate flashing (replace with actual flashing code)
            for i in range(101):
                progress.setValue(i)
                QApplication.processEvents()
                if progress.wasCanceled():
                    break
                QTimer.singleShot(50, lambda: None)
            
            if not progress.wasCanceled():
                self.show_info("Flash Complete", f"Firmware flashed to {port}")
                self.statusLabel.setText("Flashing completed")
                
        except Exception as e:
            self.show_error("Flash Error", str(e))
        finally:
            progress.close()
    
    def update_ui_state(self):
        """Enable/disable UI elements based on current state"""
        has_board = bool(self.detected_boards)
        has_key = bool(self.current_key)
        
        self.connectButton.setEnabled(has_board)
        self.exportKeyButton.setEnabled(has_key)
        self.signBinButton.setEnabled(has_key and bool(self.binFilePath.text()))
        self.signApjButton.setEnabled(has_key and bool(self.apjFilePath.text()))
        self.verifyButton.setEnabled(bool(self.binFilePath.text()) or bool(self.apjFilePath.text()))
        self.flashButton.setEnabled(has_board and bool(self.firmwarePath.text()))
    
    def show_error(self, title, message):
        """Show error message dialog"""
        QMessageBox.critical(self, title, message)
    
    def show_info(self, title, message):
        """Show information message dialog"""
        QMessageBox.information(self, title, message)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
