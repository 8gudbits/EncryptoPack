from threads import EncryptionThread, DecryptionThread
from PyQt6.QtWidgets import (
    QLineEdit,
    QMainWindow,
    QFrame,
    QPushButton,
    QProgressBar,
    QFileDialog,
    QMessageBox,
    QApplication,
    QLabel,
)
from PyQt6.QtGui import QColor, QPalette, QPixmap, QPainter, QFont, QIcon, QImage
from PyQt6.QtCore import Qt

import os
import sys
import subprocess


VERSION = "1.1"


class PlaceholderLineEdit(QLineEdit):
    """Custom QLineEdit with enhanced placeholder functionality and styling."""
    def __init__(self, placeholder='', color='gray', parent=None):
        super().__init__(parent)
        self.placeholder = placeholder
        self.placeholder_color = QColor(color)
        self.default_fg_color = self.palette().color(QPalette.ColorRole.Text)
        self.user_interaction = False
        self.user_input = False

        self.setPlaceholderText(self.placeholder)
        self.setPlaceholderColor(color)

        self.setStyleSheet(
            '''
            QLineEdit {
                background-color: #252525;
                color: white;
                border: none;
                border-bottom: 1px solid transparent;
                selection-background-color: #3D3D3D;
                border-radius: 4px;
                padding: 2px 6px;
            }

            QLineEdit:focus {
                border-bottom: 1px solid #D2691E;
            }
            '''
        )

        self.textChanged.connect(self.on_text_changed)

    def setPlaceholderColor(self, color):
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(color))
        self.setPalette(palette)

    def focusInEvent(self, event):
        super().focusInEvent(event)
        if self.text() == self.placeholder:
            self.clear()
            self.setPalette(self.default_palette())
        self.user_interaction = True

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        if not self.text():
            self.setPlaceholderText(self.placeholder)
            self.setPalette(self.placeholder_palette())
        self.user_interaction = False

    def on_text_changed(self):
        if not self.user_input:
            self.user_input = True

    def default_palette(self):
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Text, self.default_fg_color)
        return palette

    def placeholder_palette(self):
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Text, self.placeholder_color)
        return palette


class SectionLabel(QLabel):
    """Label for section headings"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QLabel {
                color: #D2691E;
                font-weight: bold;
                background-color: transparent;
                border-bottom: 1px solid #3D3D3D;
                padding: 0 0 2px 0;
            }
        """)
        self.setFixedHeight(20)


class StyledButton(QPushButton):
    """Consistently styled button"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QPushButton {
                background-color: #383838;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton:hover {
                background-color: #2F2F2F;
            }
            QPushButton:pressed {
                background-color: #202020;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
        """)


class MainWindow(QMainWindow):
    """EncryptoPack with improved design and visual organization"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"EncryptoPack {VERSION}")
        self.setFixedSize(450, 464)
        self.setWindowOpacity(0.95)

        # Create application icon
        app_icon_image = QImage(32, 32, QImage.Format.Format_ARGB32)
        app_icon_image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(app_icon_image)
        painter.setFont(QFont("Segoe UI Emoji", 20))
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(app_icon_image.rect(), Qt.AlignmentFlag.AlignCenter, "\U0001FAB6")
        painter.end()
        pixmap = QPixmap.fromImage(app_icon_image)
        self.setWindowIcon(QIcon(pixmap))

        # Create main container
        main_frame = QFrame(self)
        main_frame.setGeometry(10, 10, 430, 444)

        # Layout positions
        y_pos = 0

        # Section 1: File Selection
        file_section_label = SectionLabel("File Selection", main_frame)
        file_section_label.setGeometry(0, y_pos, 430, 20)
        y_pos += 25

        self.path_type_button = StyledButton("Folder", main_frame)
        self.path_type_button.setGeometry(0, y_pos, 56, 24)
        self.path_type_button.clicked.connect(self.path_type_button_clicked)

        self.file_path_entry = PlaceholderLineEdit(placeholder="Folder Path", color='#888', parent=main_frame)
        self.file_path_entry.setGeometry(62, y_pos, 368, 24)
        self.file_path_entry.setText(os.getcwd())
        y_pos += 30

        self.open_button = StyledButton("\U0001F5C2 \U000027A1", main_frame)
        self.open_button.setGeometry(0, y_pos, 56, 24)
        self.open_button.clicked.connect(self.open_file_explorer)

        self.select_button = StyledButton("Select File/Folder", main_frame)
        self.select_button.setGeometry(62, y_pos, 287, 24)
        self.select_button.clicked.connect(self.select_path)

        self.select_button_information = StyledButton("Info \U0001F4A1", main_frame)
        self.select_button_information.setGeometry(355, y_pos, 75, 24)
        font = self.select_button_information.font()
        font.setFamily("Segoe UI Emoji")
        font.setPointSize(10)
        self.select_button_information.setFont(font)
        self.select_button_information.clicked.connect(self.select_information_button_clicked)
        y_pos += 35

        # Section 2: Security
        security_section_label = SectionLabel("Security", main_frame)
        security_section_label.setGeometry(0, y_pos, 430, 20)
        y_pos += 25

        self.password_entry = PlaceholderLineEdit(placeholder="Password", color='#888', parent=main_frame)
        self.password_entry.setGeometry(0, y_pos, 171, 24)
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)

        self.confirm_password_entry = PlaceholderLineEdit(placeholder="Confirm Password", color='#888', parent=main_frame)
        self.confirm_password_entry.setGeometry(177, y_pos, 172, 24)
        self.confirm_password_entry.setEchoMode(QLineEdit.EchoMode.Password)

        self.password_show_button = StyledButton("Show \U0001F513", main_frame)
        self.password_show_button.setGeometry(355, y_pos, 75, 24)
        self.password_show_button.clicked.connect(self.toggle_password_visibility)
        y_pos += 30

        self.recovery_key_entry = PlaceholderLineEdit(placeholder="Recovery key file", color='#888', parent=main_frame)
        self.recovery_key_entry.setGeometry(0, y_pos, 349, 24)

        self.recovery_key_select_button = StyledButton("Select \U0001F510", main_frame)
        self.recovery_key_select_button.setGeometry(355, y_pos, 75, 24)
        self.recovery_key_select_button.clicked.connect(self.recovery_key_select_button_clicked)
        y_pos += 30

        self.iv_key_file_entry = PlaceholderLineEdit(placeholder="IV-key file", color='#888', parent=main_frame)
        self.iv_key_file_entry.setGeometry(0, y_pos, 349, 24)

        self.iv_key_file_select_button = StyledButton("Select \U0001F511", main_frame)
        self.iv_key_file_select_button.setGeometry(355, y_pos, 75, 24)
        self.iv_key_file_select_button.clicked.connect(self.iv_key_file_select_button_clicked)
        y_pos += 35

        # Section 3: Options
        options_section_label = SectionLabel("Options", main_frame)
        options_section_label.setGeometry(0, y_pos, 430, 20)
        y_pos += 25

        self.gen_recovery_key_button = StyledButton("\U0001F510 Generate recovery key file : \U0001F6AB", main_frame)
        self.gen_recovery_key_button.setGeometry(0, y_pos, 349, 24)
        self.gen_recovery_key_button.clicked.connect(self.gen_recovery_key_button_clicked)

        self.recovery_key_help_button = StyledButton("About \u2754", main_frame)
        self.recovery_key_help_button.setGeometry(355, y_pos, 75, 24)
        self.recovery_key_help_button.clicked.connect(self.recovery_key_help_button_clicked)
        y_pos += 30

        self.gen_iv_key_button = StyledButton("\U0001F511 Generate IV-key file : \U0001F6AB", main_frame)
        self.gen_iv_key_button.setGeometry(0, y_pos, 349, 24)
        self.gen_iv_key_button.clicked.connect(self.gen_iv_key_button_clicked)

        self.iv_key_help_button = StyledButton("About \u2754", main_frame)
        self.iv_key_help_button.setGeometry(355, y_pos, 75, 24)
        self.iv_key_help_button.clicked.connect(self.iv_key_help_button_clicked)
        y_pos += 30

        self.remove_files_toggle_button = StyledButton("\U0001F5D1 Remove files after encryption/decryption : \U0001F6AB", main_frame)
        self.remove_files_toggle_button.setGeometry(0, y_pos, 430, 24)
        self.remove_files_toggle_button.clicked.connect(self.remove_files_toggle_button_clicked)
        y_pos += 30

        self.toggle_show_progress_bar = StyledButton("\u231B Show encryption/decryption progress : \u2705", main_frame)
        self.toggle_show_progress_bar.setGeometry(0, y_pos, 430, 24)
        self.toggle_show_progress_bar.clicked.connect(self.toggle_show_progress_bar_clicked)
        y_pos += 35

        # Section 4: Actions
        actions_section_label = SectionLabel("Actions", main_frame)
        actions_section_label.setGeometry(0, y_pos, 430, 20)
        y_pos += 25

        self.encrypt_button = StyledButton("Encrypt", main_frame)
        self.encrypt_button.setGeometry(-2, y_pos, 214, 28)
        self.encrypt_button.setStyleSheet("background-color: #4a6741;")
        self.encrypt_button.clicked.connect(self.encrypt_button_click)

        self.decrypt_button = StyledButton("Decrypt", main_frame)
        self.decrypt_button.setGeometry(217, y_pos, 214, 28)
        self.decrypt_button.setStyleSheet("background-color: #5e3d50;")
        self.decrypt_button.clicked.connect(self.decrypt_button_click)
        y_pos += 34

        # Progress bar
        self.progress_bar = QProgressBar(main_frame)
        self.progress_bar.setGeometry(0, y_pos, 430, 24)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #252525;
                border-radius: 4px;
                text-align: center;
                height: 10px;
            }
            QProgressBar::chunk {
                background-color: #D2691E;
                border-radius: 4px;
            }
        """)

        # Create worker threads
        self.encrypt_thread = EncryptionThread()
        self.decrypt_thread = DecryptionThread()

        # Connect thread signals
        self.encrypt_thread.progress_updated.connect(self.update_progress)
        self.encrypt_thread.operation_completed.connect(self.show_success_message)
        self.encrypt_thread.error_occurred.connect(self.show_error_message)
        
        self.decrypt_thread.progress_updated.connect(self.update_progress)
        self.decrypt_thread.operation_completed.connect(self.show_success_message)
        self.decrypt_thread.error_occurred.connect(self.show_error_message)

        # Apply the color palette
        self.set_color_palette()

    def set_color_palette(self):
        """Set application color scheme"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        dark_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(24, 24, 24))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(30, 30, 30))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        dark_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        self.setPalette(dark_palette)

        # Update widget stylesheets
        dark_stylesheet = """
            QWidget {
                font-size: 9pt;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QComboBox {
                background-color: #252525;
                color: white;
                selection-background-color: #3D3D3D;
                border: 1px solid #3D3D3D;
                border-radius: 4px;
                padding: 2px 2px 2px 4px;
            }
            QComboBox:!editable {
                color: white;
            }
            QComboBox QAbstractItemView {
                background-color: #252525;
                color: white;
                selection-background-color: #3D3D3D;
                selection-color: white;
            }
            QLineEdit {
                background-color: #252525;
                color: white;
                selection-background-color: #3D3D3D;
                border: 1px solid #3D3D3D;
                border-radius: 4px;
                padding: 2px 6px;
            }
        """
        self.setStyleSheet(dark_stylesheet)
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def show_success_message(self, title, message):
        QMessageBox.information(self, title, message)
        self.progress_bar.setValue(0)
        self.enable_ui(True)
        
    def show_error_message(self, title, message):
        QMessageBox.critical(self, title, message)
        self.progress_bar.setValue(0)
        self.enable_ui(True)

    def enable_ui(self, enabled):
        self.path_type_button.setEnabled(enabled)
        self.file_path_entry.setEnabled(enabled)
        self.open_button.setEnabled(enabled)
        self.select_button.setEnabled(enabled)
        self.select_button_information.setEnabled(enabled)
        self.password_entry.setEnabled(enabled)
        self.confirm_password_entry.setEnabled(enabled)
        self.password_show_button.setEnabled(enabled)
        self.recovery_key_entry.setEnabled(enabled)
        self.recovery_key_select_button.setEnabled(enabled)
        self.iv_key_file_entry.setEnabled(enabled)
        self.iv_key_file_select_button.setEnabled(enabled)
        self.gen_recovery_key_button.setEnabled(enabled)
        self.recovery_key_help_button.setEnabled(enabled)
        self.gen_iv_key_button.setEnabled(enabled)
        self.iv_key_help_button.setEnabled(enabled)
        self.remove_files_toggle_button.setEnabled(enabled)
        self.toggle_show_progress_bar.setEnabled(enabled)
        self.encrypt_button.setEnabled(enabled)
        self.decrypt_button.setEnabled(enabled)

    def path_type_button_clicked(self):
        current_path_type = self.path_type_button.text()
        if current_path_type == "Folder":
            self.path_type_button.setText("File")
        else:
            self.path_type_button.setText("Folder")

    def open_file_explorer(self):
        if sys.platform.startswith('win'):
            subprocess.Popen(f'explorer /root,"{os.getcwd()}"', shell=False)
        else:
            subprocess.Popen(['xdg-open', os.getcwd()])

    def select_path(self):
        current_path_type = self.path_type_button.text()
        if current_path_type == "Folder":
            path = QFileDialog.getExistingDirectory(self, "Select Folder", os.getcwd())
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Select File", os.getcwd())

        if path:
            self.file_path_entry.setText(path)

    def select_information_button_clicked(self):
        QMessageBox.information(self,"Select Button Information",
            "You can choose between selecting a folder or a file by clicking on the button next to the location input box.")

    def toggle_password_visibility(self):
        if self.password_entry.echoMode() == QLineEdit.EchoMode.Password:
            self.password_entry.setEchoMode(QLineEdit.EchoMode.Normal)
            self.confirm_password_entry.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_show_button.setText("Hide  \U0001F6E1")
        else:
            self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_password_entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_show_button.setText("Show \U0001F513")

    def recovery_key_select_button_clicked(self):
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("RKEY Files (*.rkey)")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setWindowTitle("Select .rkey File")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_files = file_dialog.selectedFiles()
            path = selected_files[0]
            self.recovery_key_entry.setText(path)

    def iv_key_file_select_button_clicked(self):
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("IVKEY Files (*.ivkey)")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setWindowTitle("Select .ivkey File")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_files = file_dialog.selectedFiles()
            path = selected_files[0]
            self.iv_key_file_entry.setText(path)

    def gen_recovery_key_button_clicked(self):
        current_state = self.gen_recovery_key_button.text()
        if " \U0001F6AB" in current_state:
            self.gen_recovery_key_button.setText(current_state.replace("\U0001F6AB", "\u2705"))
        else:
            self.gen_recovery_key_button.setText(current_state.replace("\u2705", "\U0001F6AB"))

    def recovery_key_help_button_clicked(self):
        QMessageBox.information(self, "Recovery Key Information",
            "Recovery key file can be used to decrypt files if the password is forgotten. Any unauthorized person can decrypt files without the password if they get their hands on this key file, so the recovery key must be kept safe.")

    def gen_iv_key_button_clicked(self):
        current_state = self.gen_iv_key_button.text()
        if " \U0001F6AB" in current_state:
            self.gen_iv_key_button.setText(current_state.replace("\U0001F6AB", "\u2705"))
        else:
            self.gen_iv_key_button.setText(current_state.replace("\u2705", "\U0001F6AB"))
    
    def iv_key_help_button_clicked(self):
        QMessageBox.information(self, "Key File Information",
            "IV-key file works as extra security and if generated will be required alongside password to decrypt encrypted file.")

    def remove_files_toggle_button_clicked(self):
        current_state = self.remove_files_toggle_button.text()
        if " \U0001F6AB" in current_state:
            self.remove_files_toggle_button.setText(current_state.replace("\U0001F6AB", "\u2705"))
        else:
            self.remove_files_toggle_button.setText(current_state.replace("\u2705", "\U0001F6AB"))

    def toggle_show_progress_bar_clicked(self):
        current_state = self.toggle_show_progress_bar.text()
        if " \u2705" in current_state:
            self.toggle_show_progress_bar.setText(current_state.replace("\u2705", "\U0001F6AB"))
        else:
            self.toggle_show_progress_bar.setText(current_state.replace("\U0001F6AB", "\u2705"))

    def encrypt_button_click(self):
        password = self.password_entry.text()
        confirm_password = self.confirm_password_entry.text()
        file_path = self.file_path_entry.text()

        # Validate input
        if not file_path:
            QMessageBox.critical(self, "Error", "The path field cannot be left empty. Please select a valid file/folder path.")
            return

        if password.strip() == "":
            QMessageBox.critical(self, "Error", "The password field cannot be left empty. Please enter a password.")
            return

        if password != confirm_password:
            QMessageBox.critical(self, "Error", "The passwords entered do not match. Please make sure to enter the same password in both fields.")
            return

        if not (os.path.isfile(file_path) or os.path.isdir(file_path)) or not os.path.exists(file_path):
            QMessageBox.critical(self, "Error", "The file/folder path you entered is invalid. Please double-check and enter a correct path.")
            return

        # Disable UI during operation
        self.enable_ui(False)

        # Set up encryption thread
        self.encrypt_thread.setup(
            file_path,
            password,
            "\u2705" in self.gen_iv_key_button.text(),
            "\u2705" in self.gen_recovery_key_button.text(),
            "\u2705" in self.remove_files_toggle_button.text(),
            "\u2705" in self.toggle_show_progress_bar.text()
        )

        # Start thread
        self.encrypt_thread.start()

    def decrypt_button_click(self):
        recovery_key_file = self.recovery_key_entry.text()
        iv_key_file = self.iv_key_file_entry.text()
        password = self.password_entry.text()
        file_path = self.file_path_entry.text()

        # Validate input
        if not file_path:
            QMessageBox.critical(self, "Error", "The path field cannot be left empty. Please select a valid file/folder path.")
            return

        if password.strip() == "" and recovery_key_file.strip() == "":
            QMessageBox.critical(self, "Error", "The password field cannot be left empty. Please enter a password or a valid recovery key file.")
            return

        if not (os.path.isfile(file_path) or os.path.isdir(file_path)) or not os.path.exists(file_path):
            QMessageBox.critical(self, "Error", "The file/folder path you entered is invalid. Please double-check and enter a correct path.")
            return

        if not recovery_key_file.strip() == "" and not os.path.exists(recovery_key_file.strip()):
            QMessageBox.critical(self, "Error", "The selected recovery key file path is invalid. Please double-check and enter a correct path.")
            return
        elif not recovery_key_file.strip() == "" and os.path.exists(recovery_key_file.strip()):
            recovery_key_file_size = os.path.getsize(recovery_key_file.strip())
            if recovery_key_file_size < 64:
                QMessageBox.critical(self, "Error", "An error occurred during decryption: Invalid or corrupted recovery key file.")
                return

        if not iv_key_file.strip() == "" and not os.path.exists(iv_key_file.strip()):
            QMessageBox.critical(self, "Error", "The selected key file path is invalid. Please double-check and enter a correct path.")
            return

        # Set default argument value
        separate_iv_key = None
        hash_password = True
        if not iv_key_file.strip() == "":
            separate_iv_key = iv_key_file.strip()
        if not recovery_key_file.strip() == "":
            hash_password = False
            with open(recovery_key_file.strip(), 'r') as file:
                password = file.read(64)

        # Disable UI during operation
        self.enable_ui(False)

        # Set up decryption thread
        self.decrypt_thread.setup(
            file_path,
            password,
            recovery_key_file.strip(),
            iv_key_file.strip(),
            "\u2705" in self.remove_files_toggle_button.text(),
            "\u2705" in self.toggle_show_progress_bar.text(),
            hash_password,
            separate_iv_key
        )

        # Start thread
        self.decrypt_thread.start()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()

    main_window.activateWindow()
    main_window.raise_()

    sys.exit(app.exec())

