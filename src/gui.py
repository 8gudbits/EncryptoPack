from themes import UITheme
from constants import APP_NAME, CURRENT_VERSION, IV_KEY_EXT, RECOVERY_KEY_EXT
from crypto_operations import EncryptionThread, DecryptionThread

from PyQt6.QtWidgets import (
    QLineEdit,
    QMainWindow,
    QFrame,
    QPushButton,
    QProgressBar,
    QFileDialog,
    QMessageBox,
    QLabel,
)
from PyQt6.QtGui import QColor, QPalette, QPixmap, QPainter, QFont, QIcon, QImage
from PyQt6.QtCore import Qt

import os
import sys
import subprocess


class PlaceholderLineEdit(QLineEdit):
    """A QLineEdit subclass with customizable placeholder text and styling.

    Attributes:
        placeholder (str): The placeholder text to display when empty
        placeholder_color (QColor): Color for the placeholder text
        default_fg_color (QColor): Default text color
        user_interaction (bool): Tracks if user has interacted with the field
        user_input (bool): Tracks if user has entered any text
    """
    def __init__(self, placeholder='', color='gray', parent=None):
        super().__init__(parent)
        self.placeholder = placeholder
        self.placeholder_color = QColor(color)
        self.default_fg_color = self.palette().color(QPalette.ColorRole.Text)
        self.user_interaction = False
        self.user_input = False

        self.setPlaceholderText(self.placeholder)
        self.setPlaceholderColor(color)
        self.setStyleSheet(UITheme.get_placeholder_lineedit_style())

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
    """A styled QLabel subclass for section headings in the UI.
    Has fixed height and theme-specific styling.
    """
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(UITheme.get_section_label_style())
        self.setFixedHeight(20)


class StyledButton(QPushButton):
    """A QPushButton subclass with consistent theme-specific styling."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(UITheme.get_styled_button_style())


class MainWindow(QMainWindow):
    """The main application window for file encryption/decryption.

    Provides a graphical interface for:
    - File/folder selection
    - Password management
    - Encryption/decryption operations
    - Progress tracking

    Attributes:
        encrypt_thread (EncryptionThread): Handles encryption operations
        decrypt_thread (DecryptionThread): Handles decryption operations
        progress_bar (QProgressBar): Displays operation progress
    """
    def __init__(self, file_path=None):
        super().__init__()
        self.setAcceptDrops(True)
        self.setWindowTitle(f"{APP_NAME} {CURRENT_VERSION}")
        self.setFixedSize(450, 460)
        self.setWindowOpacity(0.95)

        # Create application icon
        app_icon_image = QImage(32, 32, QImage.Format.Format_ARGB32)
        app_icon_image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(app_icon_image)
        painter.setFont(QFont("Segoe UI Emoji", 20))
        painter.setPen(QColor(255, 255, 255))
        painter.drawText(app_icon_image.rect(), Qt.AlignmentFlag.AlignCenter, "\U0001FAB6") # \U0001FAB6 = 🪶
        painter.end()
        pixmap = QPixmap.fromImage(app_icon_image)
        self.setWindowIcon(QIcon(pixmap))

        # Create main container
        main_frame = QFrame(self)
        main_frame.setGeometry(10, 10, 426, 444)

        # Layout positions
        y_pos = 0

        # Section 1: File Selection
        file_section_label = SectionLabel("File Selection", main_frame)
        file_section_label.setGeometry(0, y_pos, 430, 20)
        y_pos += 25

        self.file_path_entry = PlaceholderLineEdit(placeholder="File/Folder Path", color='#888', parent=main_frame)
        self.file_path_entry.setGeometry(0, y_pos, 430, 24)
        self.file_path_entry.setText(os.getcwd())
        y_pos += 30

        self.open_button = StyledButton("\U0001F5C2 Open Location", main_frame) # \U0001F5C2 = 🗂️
        self.open_button.setGeometry(0, y_pos, 143, 24)
        self.open_button.clicked.connect(self.open_file_manager)

        self.select_file_button = StyledButton("\U0001F4C4 Select File", main_frame) # \U0001F4C4 = 📄
        self.select_file_button.setGeometry(148, y_pos, 143, 24)
        self.select_file_button.clicked.connect(self.select_file)

        self.select_folder_button = StyledButton("\U0001F5C2 Select Folder", main_frame) # \U0001F5C2 = 🗂️
        self.select_folder_button.setGeometry(296, y_pos, 134, 24)
        self.select_folder_button.clicked.connect(self.select_folder)
        y_pos += 35

        # Auto-select file if one was passed
        if file_path and os.path.isfile(file_path):
            self.file_path_entry.setText(file_path)

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

        self.password_show_button = StyledButton("Show \U0001F513", main_frame) # \U0001F513 = 🔓
        self.password_show_button.setGeometry(355, y_pos, 75, 24)
        self.password_show_button.clicked.connect(self.toggle_password_visibility)
        y_pos += 30

        self.recovery_key_entry = PlaceholderLineEdit(placeholder="Recovery key file", color='#888', parent=main_frame)
        self.recovery_key_entry.setGeometry(0, y_pos, 349, 24)

        self.recovery_key_select_button = StyledButton("Select \U0001F510", main_frame) # \U0001F510 = 🔐
        self.recovery_key_select_button.setGeometry(355, y_pos, 75, 24)
        self.recovery_key_select_button.clicked.connect(self.recovery_key_select_button_clicked)
        y_pos += 30

        self.iv_key_file_entry = PlaceholderLineEdit(placeholder="IV-key file", color='#888', parent=main_frame)
        self.iv_key_file_entry.setGeometry(0, y_pos, 349, 24)

        self.iv_key_file_select_button = StyledButton("Select \U0001F511", main_frame) # \U0001F511 = 🔑
        self.iv_key_file_select_button.setGeometry(355, y_pos, 75, 24)
        self.iv_key_file_select_button.clicked.connect(self.iv_key_file_select_button_clicked)
        y_pos += 35

        # Section 3: Options
        options_section_label = SectionLabel("Options", main_frame)
        options_section_label.setGeometry(0, y_pos, 430, 20)
        y_pos += 25

        self.gen_recovery_key_button = StyledButton("\U0001F510 Generate recovery key file : \U0001F7E5", main_frame) # \U0001F510 = 🔐 # \U0001F7E5 = 🟥
        self.gen_recovery_key_button.setGeometry(0, y_pos, 349, 24)
        self.gen_recovery_key_button.clicked.connect(self.gen_recovery_key_button_clicked)

        self.recovery_key_help_button = StyledButton("About \U00002754", main_frame) # \U00002754 = ❔
        self.recovery_key_help_button.setGeometry(355, y_pos, 75, 24)
        self.recovery_key_help_button.clicked.connect(self.recovery_key_help_button_clicked)
        y_pos += 30

        self.gen_iv_key_button = StyledButton("\U0001F511 Generate IV-key file : \U0001F7E5", main_frame) # \U0001F511 = 🔑 # \U0001F7E5 = 🟥
        self.gen_iv_key_button.setGeometry(0, y_pos, 349, 24)
        self.gen_iv_key_button.clicked.connect(self.gen_iv_key_button_clicked)

        self.iv_key_help_button = StyledButton("About \U00002754", main_frame) # \U00002754 = ❔
        self.iv_key_help_button.setGeometry(355, y_pos, 75, 24)
        self.iv_key_help_button.clicked.connect(self.iv_key_help_button_clicked)
        y_pos += 30

        self.remove_files_toggle_button = StyledButton("\U0001F5D1 Remove files after encryption/decryption : \U0001F7E5", main_frame) # \U0001F5D1 = 🗑️ # \U0001F7E5 = 🟥
        self.remove_files_toggle_button.setGeometry(0, y_pos, 430, 24)
        self.remove_files_toggle_button.clicked.connect(self.remove_files_toggle_button_clicked)
        y_pos += 30

        self.toggle_show_progress_bar = StyledButton("\U0000231B Show encryption/decryption progress : \U00002705", main_frame) # \U0000231B = ⌛ # \U00002705 = ✅
        self.toggle_show_progress_bar.setGeometry(0, y_pos, 430, 24)
        self.toggle_show_progress_bar.clicked.connect(self.toggle_show_progress_bar_clicked)
        y_pos += 35

        # Section 4: Actions
        actions_section_label = SectionLabel("Actions", main_frame)
        actions_section_label.setGeometry(0, y_pos, 430, 20)
        y_pos += 25

        self.encrypt_button = StyledButton("Encrypt", main_frame)
        self.encrypt_button.setGeometry(0, y_pos, 210, 24)
        self.encrypt_button.setStyleSheet(UITheme.get_encrypt_button_style())
        self.encrypt_button.clicked.connect(self.encrypt_button_click)

        self.decrypt_button = StyledButton("Decrypt", main_frame)
        self.decrypt_button.setGeometry(216, y_pos, 210, 24)
        self.decrypt_button.setStyleSheet(UITheme.get_decrypt_button_style())
        self.decrypt_button.clicked.connect(self.decrypt_button_click)
        y_pos += 30

        # Progress bar
        self.progress_bar = QProgressBar(main_frame)
        self.progress_bar.setGeometry(0, y_pos, 430, 24)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet(UITheme.get_progress_bar_style())

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
        """Applies the UI theme's color palette and stylesheet to the window."""
        self.setPalette(UITheme.get_color_palette())
        self.setStyleSheet(UITheme.get_stylesheet())

    def dragEnterEvent(self, event):
        """Handles the drag enter event when a user drags an object over the window.

        Args:
            event (QDragEnterEvent): The drag enter event triggered by the user.
        """
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        """Handles the drop event when a user releases a dragged object onto the window.

        Args:
            event (QDropEvent): The drop event containing dropped data.
        """
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()

            # Check file extension to determine where to place it
            ext = os.path.splitext(file_path)[1].lower()

            if ext == IV_KEY_EXT:
                self.iv_key_file_entry.setText(file_path)
            elif ext == RECOVERY_KEY_EXT:
                self.recovery_key_entry.setText(file_path)
            else:
                self.file_path_entry.setText(file_path)


    def update_progress(self, value):
        """Updates the progress bar with the current operation progress.

        Args:
            value (int): Progress percentage (0-100)
        """
        self.progress_bar.setValue(value)

    def show_success_message(self, title, message):
        """Displays a success message dialog.

        Args:
            title (str): Dialog window title
            message (str): Message content
        """
        QMessageBox.information(self, title, message)
        self.progress_bar.setValue(0)
        self.enable_ui(True)

    def show_error_message(self, title, message):
        """Displays an error message dialog.

        Args:
            title (str): Dialog window title
            message (str): Error message content
        """
        QMessageBox.critical(self, title, message)
        self.progress_bar.setValue(0)
        self.enable_ui(True)

    def enable_ui(self, enabled):
        """Enables or disables all interactive UI elements.

        Args:
            enabled (bool): True to enable, False to disable
        """
        self.file_path_entry.setEnabled(enabled)
        self.open_button.setEnabled(enabled)
        self.select_file_button.setEnabled(enabled)
        self.select_folder_button.setEnabled(enabled)
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

    def open_file_manager(self):
        """Opens the system file manager at the current path."""
        path = self.file_path_entry.text()
        if not path:
            path = os.getcwd()

        # If path is a file, get its directory
        if os.path.isfile(path):
            path = os.path.dirname(path)

        # If path doesn't exist, use current directory
        if not os.path.exists(path):
            path = os.getcwd()

        if sys.platform.startswith('win'):
            subprocess.Popen(f'explorer "{path}"', shell=False)
        else:
            subprocess.Popen(['xdg-open', path])

    def select_file(self):
        """Opens a file dialog and sets the selected file path."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File", os.getcwd())
        if path:
            self.file_path_entry.setText(path)

    def select_folder(self):
        """Opens a folder dialog and sets the selected folder path."""
        path = QFileDialog.getExistingDirectory(self, "Select Folder", os.getcwd())
        if path:
            self.file_path_entry.setText(path)

    def toggle_password_visibility(self):
        """Toggles password field visibility between plain text and hidden."""
        if self.password_entry.echoMode() == QLineEdit.EchoMode.Password:
            self.password_entry.setEchoMode(QLineEdit.EchoMode.Normal)
            self.confirm_password_entry.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_show_button.setText("Hide \U0001F512") # \U0001F6E1 = 🔒
        else:
            self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_password_entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_show_button.setText("Show \U0001F513") # \U0001F513 = 🔓

    def recovery_key_select_button_clicked(self):
        """Handles recovery key file selection."""
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("RKEY Files (*.rkey)")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setWindowTitle("Select .rkey File")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_files = file_dialog.selectedFiles()
            path = selected_files[0]
            self.recovery_key_entry.setText(path)

    def iv_key_file_select_button_clicked(self):
        """Handles IV key file selection."""
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("IVKEY Files (*.ivkey)")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setWindowTitle("Select .ivkey File")
        if file_dialog.exec() == QFileDialog.DialogCode.Accepted:
            selected_files = file_dialog.selectedFiles()
            path = selected_files[0]
            self.iv_key_file_entry.setText(path)

    def gen_recovery_key_button_clicked(self):
        """Toggles recovery key generation option state."""
        current_state = self.gen_recovery_key_button.text()
        if " \U0001F7E5" in current_state: # \U0001F7E5 = 🟥
            self.gen_recovery_key_button.setText(current_state.replace("\U0001F7E5", "\U00002705")) # \U0001F7E5 = 🟥 # \U00002705 = ✅
        else:
            self.gen_recovery_key_button.setText(current_state.replace("\U00002705", "\U0001F7E5")) # \U0001F7E5 = 🟥 # \U00002705 = ✅

    def recovery_key_help_button_clicked(self):
        """Displays information about recovery key functionality."""
        QMessageBox.information(self, "Recovery Key Information",
            "Recovery key file can be used to decrypt files if the password is forgotten. Any unauthorized person can decrypt files without the password if they get their hands on this key file, so the recovery key must be kept safe.")

    def gen_iv_key_button_clicked(self):
        """Toggles IV key generation option state."""
        current_state = self.gen_iv_key_button.text()
        if " \U0001F7E5" in current_state: # \U0001F7E5 = 🟥
            self.gen_iv_key_button.setText(current_state.replace("\U0001F7E5", "\U00002705")) # \U0001F7E5 = 🟥 # \U00002705 = ✅
        else:
            self.gen_iv_key_button.setText(current_state.replace("\U00002705", "\U0001F7E5")) # \U0001F7E5 = 🟥 # \U00002705 = ✅
    
    def iv_key_help_button_clicked(self):
        """Displays information about IV key functionality."""
        QMessageBox.information(self, "Key File Information",
            "IV-key file works as extra security and if generated will be required alongside password to decrypt encrypted file.")

    def remove_files_toggle_button_clicked(self):
        """Toggles post-operation file removal option state."""
        current_state = self.remove_files_toggle_button.text()
        if " \U0001F7E5" in current_state: # \U0001F7E5 = 🟥
            self.remove_files_toggle_button.setText(current_state.replace("\U0001F7E5", "\U00002705")) # \U0001F7E5 = 🟥 # \U00002705 = ✅
        else:
            self.remove_files_toggle_button.setText(current_state.replace("\U00002705", "\U0001F7E5")) # \U0001F7E5 = 🟥 # \U00002705 = ✅

    def toggle_show_progress_bar_clicked(self):
        """Toggles progress bar visibility option state."""
        current_state = self.toggle_show_progress_bar.text()
        if " \U00002705" in current_state:
            self.toggle_show_progress_bar.setText(current_state.replace("\U00002705", "\U0001F7E5")) # \U0001F7E5 = 🟥 # \U00002705 = ✅
        else:
            self.toggle_show_progress_bar.setText(current_state.replace("\U0001F7E5", "\U00002705")) # \U0001F7E5 = 🟥 # \U00002705 = ✅

    def encrypt_button_click(self):
        """Validates inputs and initiates encryption operation."""
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
            "\U00002705" in self.gen_iv_key_button.text(),          # \U00002705 = ✅
            "\U00002705" in self.gen_recovery_key_button.text(),    # \U00002705 = ✅
            "\U00002705" in self.remove_files_toggle_button.text(), # \U00002705 = ✅
            "\U00002705" in self.toggle_show_progress_bar.text()    # \U00002705 = ✅
        )

        # Start thread
        self.encrypt_thread.start()

    def decrypt_button_click(self):
        """Validates inputs and initiates decryption operation."""
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
            "\U00002705" in self.remove_files_toggle_button.text(), # \U00002705 = ✅
            "\U00002705" in self.toggle_show_progress_bar.text(),   # \U00002705 = ✅
            hash_password,
            separate_iv_key
        )

        # Start thread
        self.decrypt_thread.start()

