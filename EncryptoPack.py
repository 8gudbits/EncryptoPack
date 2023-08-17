from PyQt5.QtWidgets import (
    QLineEdit, QMainWindow, QFrame, QPushButton, QProgressBar, QFileDialog, QMessageBox, QApplication)
from PyQt5.QtGui import QColor, QPalette, QPixmap, QPainter, QFont, QIcon
from PyQt5.QtCore import Qt

import os
import sys
import subprocess
import psutil
import tarfile
import hashlib
import string
import random

from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES


def get_optimal_block_size():
    """Determine the optimal block size based on the available RAM.

    Returns:
        int: The optimal block size in bytes.
    """
    try:
        available_ram = psutil.virtual_memory().available
        gb_ram = available_ram // (1024 ** 3)

        if gb_ram <= 1:    return 65536    # 64 KiB block size
        elif gb_ram <= 2:  return 131072   # 128 KiB block size
        elif gb_ram <= 3:  return 262144   # 256 KiB block size
        elif gb_ram <= 4:  return 524288   # 512 KiB block size
        elif gb_ram <= 6:  return 524288   # 512 KiB block size
        elif gb_ram <= 8:  return 1048576  # 1 MiB block size
        elif gb_ram <= 12: return 1048576  # 1 MiB block size
        elif gb_ram <= 16: return 1572864  # 1.5 MiB block size
        elif gb_ram <= 24: return 1572864  # 1.5 MiB block size
        elif gb_ram <= 32: return 3145728  # 3 MiB block size
        elif gb_ram >= 32: return 3145728  # 3 MiB block size
    except:
        return 524288   # 512 KiB block size


def generate_unique_file_name(file_path, add_extension=".pack"):
    """Generate a unique file name by appending a counter if the file already exists.

    Args:
        file_path (str): The original file path.
        add_extension (str, optional): Additional extension to append. Defaults to ".pack".

    Returns:
        str: The unique file name.
    """
    if os.path.isfile(file_path) and not os.path.exists(f"{file_path}{add_extension}"):
        return f"{file_path}{add_extension}"
    elif os.path.isfile(file_path) and os.path.exists(f"{file_path}{add_extension}"):
        file_directory = os.path.dirname(file_path)
        base_name, extension = os.path.splitext(os.path.basename(file_path))
        unique_name = base_name
        counter = 1

        while os.path.exists(os.path.join(file_directory, f"{unique_name} ({counter}){extension}{add_extension}")):
            counter += 1

        if extension:
            return os.path.join(file_directory, f"{unique_name} ({counter}){extension}{add_extension}")
        else:
            return os.path.join(file_directory, f"{unique_name} ({counter}){add_extension}")

    elif os.path.isdir(file_path) and not os.path.exists(os.path.join(file_path, f"{os.path.basename(file_path)}{add_extension}")):
        return os.path.join(file_path, f"{os.path.basename(file_path)}{add_extension}")

    elif os.path.isdir(file_path) and os.path.exists(os.path.join(file_path, f"{os.path.basename(file_path)}{add_extension}")):
        base_folder_name = os.path.basename(os.path.normpath(file_path))
        unique_folder_name = base_folder_name
        counter = 1

        while os.path.exists(os.path.join(file_path, unique_folder_name + add_extension)):
            unique_folder_name = f"{base_folder_name} ({counter})"
            counter += 1

        return os.path.join(file_path, unique_folder_name + add_extension)


def generate_unique_key_file_name(file_path, add_extension=".key"):
    """Generate a unique key file name by appending a counter if the file already exists.

    Args:
        file_path (str): The original file path.
        add_extension (str, optional): Additional extension to append. Defaults to ".key".

    Returns:
        str: The unique file name.
    """
    if not os.path.exists(f"{file_path}_{add_extension}"):
        return f"{file_path}_{add_extension}"
    elif os.path.exists(f"{file_path}_{add_extension}"):
        base_name, extension = os.path.splitext(os.path.basename(file_path))
        counter = 1

        while os.path.exists(os.path.join(f"{base_name}_{counter}{extension}{add_extension}")):
            counter += 1

        if extension:
            return os.path.join(f"{base_name}_{counter}{extension}{add_extension}")
        else:
            return os.path.join(f"{base_name}_{counter}{add_extension}")


def generate_random_string(length):
    """Generate a random string of specified length.

    Args:
        length (int): The length of the random string to generate.

    Returns:
        str: The randomly generated string.
    """
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


class PlaceholderLineEdit(QLineEdit):
    """This custom line edit widget provides a placeholder text that is displayed when the line edit
    is empty and does not have focus. It also allows customizing the color of the placeholder text.

    Args:
        placeholder (str, optional): The text to be displayed as the placeholder. Defaults to ''.
        color (str, optional): The color of the placeholder text. Accepts color names or hexadecimal
            color codes. Defaults to 'gray'.
        parent (QWidget, optional): The parent widget. Defaults to None.

    Attributes:
        placeholder (str): The placeholder text.
        placeholder_color (QColor): The color of the placeholder text.
        default_fg_color (QColor): The default foreground color of the line edit text.
        user_interaction (bool): A flag indicating whether the user has interacted with the line edit.
        user_input (bool): A flag indicating whether the user has entered any input.
    """
    def __init__(self, placeholder='', color='gray', parent=None):
        super().__init__(parent)
        self.placeholder = placeholder
        self.placeholder_color = QColor(color)
        self.default_fg_color = self.palette().color(QPalette.Text)
        self.user_interaction = False  # Track user interaction
        self.user_input = False  # Track whether the user has entered any input

        # Set the placeholder text and color
        self.setPlaceholderText(self.placeholder)
        self.setPlaceholderColor(color)

        # Set the stylesheet for the QLineEdit
        self.setStyleSheet(
            '''
            QLineEdit {
                background-color: #252525;
                color: white;
                border: none;
                border-bottom: 1px solid transparent;
                selection-background-color: #3D3D3D;
            }

            QLineEdit:focus {
                border-bottom: 1px solid #D2691E;
            }
            '''
        )

        # Connect the textChanged signal to the on_text_changed slot
        self.textChanged.connect(self.on_text_changed)

    def setPlaceholderColor(self, color):
        """Set the color of the placeholder text.

        Args:
            color (str): The color of the placeholder text. Accepts color names or hexadecimal
                color codes.
        """
        palette = self.palette()
        palette.setColor(QPalette.PlaceholderText, QColor(color))
        self.setPalette(palette)
    
    def focusInEvent(self, event):
        """Handle the focus in event.

        This method is called when the line edit receives focus. It clears the line edit if the
        current text is the placeholder and sets the user_interaction flag to True.

        Args:
            event (QFocusEvent): The focus in event object.
        """
        super().focusInEvent(event)
        
        # Clear the QLineEdit if the current text is the placeholder
        if self.text() == self.placeholder:
            self.clear()
            self.setPalette(self.default_palette())
        
        # Set the user_interaction flag to True
        self.user_interaction = True

    def focusOutEvent(self, event):
        """Handle the focus out event.

        This method is called when the line edit loses focus. It sets the placeholder text and
        palette if the line edit is empty and sets the user_interaction flag to False.

        Args:
            event (QFocusEvent): The focus out event object.
        """
        super().focusOutEvent(event)
        
        # Set the placeholder text and palette if the QLineEdit is empty
        if not self.text():
            self.setPlaceholderText(self.placeholder)
            self.setPalette(self.placeholder_palette())
        
        # Set the user_interaction flag to False
        self.user_interaction = False

    def on_text_changed(self):
        """Handle the text changed event."""
        
        # Set the user_input flag to True if it was False
        if not self.user_input:
            self.user_input = True

    def default_palette(self):
        """Get the default palette with the original text color.

        Returns:
            QPalette: The default palette with the original text color.
        """
        palette = self.palette()
        palette.setColor(QPalette.Text, self.default_fg_color)
        return palette

    def placeholder_palette(self):
        """Get the palette with the placeholder text color.

        Returns:
            QPalette: The palette with the placeholder text color.
        """
        palette = self.palette()
        palette.setColor(QPalette.Text, self.placeholder_color)
        return palette


class MainWindow(QMainWindow):
    """The main window of the application."""

    def __init__(self):
        """Initializes the MainWindow."""
        super().__init__()

        # Set window properties
        self.setWindowTitle("EncryptoPack")
        self.setFixedSize(450, 346)
        self.setWindowOpacity(0.95)

        # Set application window icon
        # Create an emoji icon using QPainter and set it as the window icon
        app_icon_emoji = QPixmap(32, 32)
        app_icon_emoji.fill(Qt.transparent)  # Set transparent background
        painter = QPainter(app_icon_emoji)
        painter.setFont(QFont("Segoe UI Emoji", 20))  # Set the font and size
        painter.drawText(app_icon_emoji.rect(), Qt.AlignCenter, "\U0001FAB6") # \U0001FAB6(🪶)
        painter.end()
        self.setWindowIcon(QIcon(app_icon_emoji))

        # Create and position UI elements
        self.path_frame = QFrame(self)
        self.path_frame.setGeometry(10, 10, 430, 24)

        # Button to toggle selection type between file and folder
        self.path_type_button = QPushButton(self.path_frame)
        self.path_type_button.setGeometry(0, 0, 56, 24)
        self.path_type_button.setText("Folder")
        self.path_type_button.clicked.connect(self.path_type_button_clicked)

        # Input box to show the selected file or folder path
        self.file_path_entry = PlaceholderLineEdit(placeholder="Folder Path", color='gray', parent=self.path_frame)
        self.file_path_entry.setGeometry(62, 0, 368, 24)
        self.file_path_entry.setText(os.getcwd())

        # Frame for multiple widgets
        self.button_frame = QFrame(self)
        self.button_frame.setGeometry(10, 40, 430, 24)

        # Button to open the file explorer in current dir
        self.open_button = QPushButton(self.button_frame)
        self.open_button.setGeometry(0, 0, 56, 24)
        self.open_button.setText("\U0001F5C2 \U000027A1") # \U0001F5C2(🗂️) # \U000027A1(➡️)
        self.open_button.clicked.connect(self.open_file_explorer)

        # Button to open file explorer for file or folder selection
        self.select_button = QPushButton(self.button_frame)
        self.select_button.setGeometry(62, 0, 287, 24)
        self.select_button.setText("Select File/Folder")
        self.select_button.clicked.connect(self.select_path)

        # Button to show information about how to select file or folder
        self.select_button_information = QPushButton(self.button_frame)
        self.select_button_information.setGeometry(355, 0, 75, 24)
        self.select_button_information.setText(" Info \U00002139") # \U00002139(ℹ️)
        font = self.select_button_information.font()
        font.setFamily("Segoe UI Emoji"); font.setPointSize(10)
        self.select_button_information.setFont(font)
        self.select_button_information.clicked.connect(self.select_information_button_clicked)

        # Frame for password entry widgets
        self.password_frame = QFrame(self)
        self.password_frame.setGeometry(10, 70, 430, 24)

        # Custom entry widget to take password input
        self.password_entry = PlaceholderLineEdit(placeholder="Password (Must always provide)", color='gray', parent=self.password_frame)
        self.password_entry.setGeometry(0, 0, 171, 24)
        self.password_entry.setEchoMode(QLineEdit.Password)

        # Entry box to conform typed password
        self.confirm_password_entry = PlaceholderLineEdit(placeholder="Confirm Password(For encryption)", color='gray', parent=self.password_frame)
        self.confirm_password_entry.setGeometry(177, 0, 172, 24)
        self.confirm_password_entry.setEchoMode(QLineEdit.Password)

        # Button to show or hide password
        self.password_show_button = QPushButton(self.password_frame)
        self.password_show_button.setGeometry(355, 0, 75, 24)
        self.password_show_button.setText("Show \U0001F513")
        self.password_show_button.clicked.connect(self.toggle_password_visibility)

        # Frame for recovery key entry
        self.recovery_key_entry_frame = QFrame(self)
        self.recovery_key_entry_frame.setGeometry(10, 100, 430, 24)

        # Entry for selecting recovery key (if needed)
        self.recovery_key_entry = PlaceholderLineEdit(placeholder="Recovery key file (Optional for decryption)", color='gray', parent=self.recovery_key_entry_frame)
        self.recovery_key_entry.setGeometry(0, 0, 349, 24)
        self.recovery_key_entry.setEchoMode(QLineEdit.Normal)

        # Button to select recovery key file
        self.recovery_key_select_button = QPushButton(self.recovery_key_entry_frame)
        self.recovery_key_select_button.setGeometry(355, 0, 75, 24)
        self.recovery_key_select_button.setText("Select \U0001F510")
        self.recovery_key_select_button.clicked.connect(self.recovery_key_select_button_clicked)

        # Frame for iv key entry widgets
        self.iv_key_file_entry_frame = QFrame(self)
        self.iv_key_file_entry_frame.setGeometry(10, 130, 430, 24)

        # Entry box for selecting iv key file
        self.iv_key_file_entry = PlaceholderLineEdit(placeholder="Key file (Must for decryption if generated)", color='gray', parent=self.iv_key_file_entry_frame)
        self.iv_key_file_entry.setGeometry(0, 0, 349, 24)
        self.iv_key_file_entry.setEchoMode(QLineEdit.Normal)

        # Button to select iv key file
        self.iv_key_file_select_button = QPushButton(self.iv_key_file_entry_frame)
        self.iv_key_file_select_button.setGeometry(355, 0, 75, 24)
        self.iv_key_file_select_button.setText("Select \U0001F511")
        self.iv_key_file_select_button.clicked.connect(self.iv_key_file_select_button_clicked)

        # Widgets to generate recovery key file
        self.gen_recovery_key_button_frame = QFrame(self)
        self.gen_recovery_key_button_frame.setGeometry(10, 160, 430, 24)

        self.gen_recovery_key_button = QPushButton(self.gen_recovery_key_button_frame)
        self.gen_recovery_key_button.setGeometry(0, 0, 349, 24)
        self.gen_recovery_key_button.setText("Generate recovery key \U0001F510 : \u274C (Disabled)")
        self.gen_recovery_key_button.clicked.connect(self.gen_recovery_key_button_clicked)

        # Button to show information about recovery key
        self.recovery_key_help_button = QPushButton(self.gen_recovery_key_button_frame)
        self.recovery_key_help_button.setGeometry(355, 0, 75, 24)
        self.recovery_key_help_button.setText("About \u2754")
        self.recovery_key_help_button.clicked.connect(self.recovery_key_help_button_clicked)

        # Widgets to generate iv key file
        self.gen_iv_key_button_frame = QFrame(self)
        self.gen_iv_key_button_frame.setGeometry(10, 190, 430, 24)

        self.gen_iv_key_button = QPushButton(self.gen_iv_key_button_frame)
        self.gen_iv_key_button.setGeometry(0, 0, 349, 24)
        self.gen_iv_key_button.setText("Generate key file \U0001F511 : \u274C (Disabled)")
        self.gen_iv_key_button.clicked.connect(self.gen_iv_key_button_clicked)

        # Button to show information about the iv key file
        self.iv_key_help_button = QPushButton(self.gen_iv_key_button_frame)
        self.iv_key_help_button.setGeometry(355, 0, 75, 24)
        self.iv_key_help_button.setText("About \u2754")
        self.iv_key_help_button.clicked.connect(self.iv_key_help_button_clicked)

        # Frame for a toggle button
        self.remove_files_toggle_button_frame = QFrame(self)
        self.remove_files_toggle_button_frame.setGeometry(10, 220, 430, 24)

        # Option to toggle between keep or rmemove files after operation
        self.remove_files_toggle_button = QPushButton(self.remove_files_toggle_button_frame)
        self.remove_files_toggle_button.setGeometry(0, 0, 430, 24)
        self.remove_files_toggle_button.setText("Remove files after encryption/decryption \U0001F5D1 : \u274C (Disabled)")
        self.remove_files_toggle_button.clicked.connect(self.remove_files_toggle_button_clicked)

        # Widgets to enable or diable show progress bar
        self.toggle_show_progress_bar_frame = QFrame(self)
        self.toggle_show_progress_bar_frame.setGeometry(10, 250, 430, 24)

        self.toggle_show_progress_bar = QPushButton(self.toggle_show_progress_bar_frame)
        self.toggle_show_progress_bar.setGeometry(0, 0, 430, 24)
        self.toggle_show_progress_bar.setText("Show encryption/decryption progress : \u2705 (Enabled)")
        self.toggle_show_progress_bar.clicked.connect(self.toggle_show_progress_bar_clicked)

        # Encrypt and decrypt buttons
        self.action_frame = QFrame(self)
        self.action_frame.setGeometry(10, 280, 430, 24)

        self.encrypt_button = QPushButton(self.action_frame)
        self.encrypt_button.setGeometry(0, 0, 212, 24)
        self.encrypt_button.setText("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt_button_click)

        self.decrypt_button = QPushButton(self.action_frame)
        self.decrypt_button.setGeometry(217, 0, 212, 24)
        self.decrypt_button.setText("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt_button_click)

        # Progress bar frame and progress bar
        self.progress_bar_frame = QFrame(self)
        self.progress_bar_frame.setGeometry(10, 310, 430, 24)

        self.progress_bar = QProgressBar(self.progress_bar_frame)
        self.progress_bar.setGeometry(0, 0, 430, 24)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet(
            """
            QProgressBar {
                border: none;
                background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                                  stop: 0 #333333, stop: 1 #666666);
                border-radius: 10px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                                  stop: 0 #D2691E, stop: 0.5 #CD853F, stop: 1 #DAA520);
                border-radius: 10px;
            }
            """
        )

        # Apply the color palette
        self.set_color_palette()

    def set_color_palette(self):
        """
        Set the dark color palette for the application.
        """
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(30, 30, 30))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(24, 24, 24))
        dark_palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(dark_palette)

        # Update widget stylesheets
        dark_stylesheet = """
            QComboBox {
                background-color: #252525;
                color: white;
                selection-background-color: #3D3D3D;
                border: 2px solid #3D3D3D;
                border-radius: 10px;
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
                border-radius: 10px;
                padding: 2px;
            }
            QPushButton {
                background-color: #383838;
                color: white;
                border: none;
                border-radius: 10px;
                padding: 5px;
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
        """
        self.setStyleSheet(dark_stylesheet)
    
    def compress_directory(self, folder_path, compressed_file_path):
        """Compress a directory into a tar file.

        Args:
            folder_path (str): Path to the directory to be compressed.
            compressed_file_path (str): Path to the compressed tar file.

        Returns:
            list: List of file paths that were successfully compressed.
        """
        compressed_files = []
        failed_list = []

        empty_file_path = os.path.join(folder_path, "~encrypto_pack")
        with open(empty_file_path, "w") as file:
            file.write("encrypto_packed_this_tar_file")

        with tarfile.open(compressed_file_path, 'w') as compressed_file:
            for root, dirs, files in os.walk(folder_path):
                for dir in dirs:
                    dir_path = os.path.join(root, dir)
                    relative_path = os.path.relpath(dir_path, folder_path)
                    compressed_file.add(dir_path, arcname=relative_path)

                for file in files:
                    file_path = os.path.join(root, file)

                    if file_path == os.path.abspath(__file__) or file_path == compressed_file_path:
                        continue

                    try:
                        relative_path = os.path.relpath(file_path, folder_path)
                        compressed_file.add(file_path, arcname=relative_path)
                        compressed_files.append(file_path)
                    except Exception as e:
                        failed_list.append(file_path)

        os.remove(empty_file_path)

        if not compressed_files:
            os.remove(compressed_file_path)
            QMessageBox.critical(self, "Error info", "No files were successfully encrypted, this could be due to permission error.")
        
        if failed_list:
            QMessageBox.warning("Warning", f"Failed to access file(s):\n\n{', '.join(failed_list)}")

        return compressed_files

    def path_type_button_clicked(self):
        """Toggle the path type button text between "Folder" and "File"."""
        current_path_type = self.path_type_button.text()
        if current_path_type == "Folder":
            self.path_type_button.setText("File")
        else:
            self.path_type_button.setText("Folder")

    def open_file_explorer(self):
        """ Open the file explorer to the current working directory."""
        if sys.platform.startswith('win'):
            subprocess.Popen(f'explorer /root,"{os.getcwd()}"', shell=False)
        else:
            subprocess.Popen(['xdg-open', os.getcwd()])

    def select_path(self):
        """Open a file dialog to select a folder or file path."""
        current_path_type = self.path_type_button.text()
        if current_path_type == "Folder":
            path = QFileDialog.getExistingDirectory(self, "Select Folder", os.getcwd())
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Select File", os.getcwd())

        if path:
            self.file_path_entry.setText(path)
    
    def select_information_button_clicked(self):
        """Show information about the select button in a message box."""
        QMessageBox.information(self,"Select Button Information",
            "You can choose between selecting a folder or a file by clicking on the button next to the location input box.")

    def toggle_password_visibility(self):
        """Toggle the visibility of the password entry field."""
        if self.password_entry.echoMode() == QLineEdit.Password:
            self.password_entry.setEchoMode(QLineEdit.Normal)
            self.confirm_password_entry.setEchoMode(QLineEdit.Normal)
            self.password_show_button.setText("Hide  \U0001F6E1")
        else:
            self.password_entry.setEchoMode(QLineEdit.Password)
            self.confirm_password_entry.setEchoMode(QLineEdit.Password)
            self.password_show_button.setText("Show \U0001F513")

    def recovery_key_select_button_clicked(self):
        """Handle the click event of the 'recovery_key_select_button' button."""
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("RKEY Files (*.rkey)")
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setWindowTitle("Select .rkey File")
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            path = selected_files[0]  # Get the first selected file path
            self.recovery_key_entry.setText(path)

    def iv_key_file_select_button_clicked(self):
        """Handle the click event of the key file select button."""
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("IVKEY Files (*.ivkey)")
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setWindowTitle("Select .ivkey File")
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            path = selected_files[0]  # Get the first selected file path
            self.iv_key_file_entry.setText(path)
    
    def gen_recovery_key_button_clicked(self):
        """Handle the click event of the generate recovery key button."""
        current_state = self.gen_recovery_key_button.text()
        if current_state == "Generate recovery key \U0001F510 : \u274C (Disabled)":
            self.gen_recovery_key_button.setText("Generate recovery key \U0001F510 : \u2705 (Enabled)")
        else:
            self.gen_recovery_key_button.setText("Generate recovery key \U0001F510 : \u274C (Disabled)")
    
    def recovery_key_help_button_clicked(self):
        """Show information about the recovery key in a message box."""
        QMessageBox.information(self, "Recovery Key Information",
            "Recovery key can be used to decrypt files if the password is forgotten. Any unauthorized person can decrypt files without the password if they get their hands on this key file, so the recovery key must be kept safe.")

    def gen_iv_key_button_clicked(self):
        """Handle the click event of the generate key file button."""
        current_state = self.gen_iv_key_button.text()
        if current_state == "Generate key file \U0001F511 : \u274C (Disabled)":
            self.gen_iv_key_button.setText("Generate key file \U0001F511 : \u2705 (Enabled)")
        else:
            self.gen_iv_key_button.setText("Generate key file \U0001F511 : \u274C (Disabled)")
    
    def iv_key_help_button_clicked(self):
        """Show information about the key file in a message box."""
        QMessageBox.information(self, "Key File Information",
            "Key file works as extra security and if generated will be required alongside password to decrypt encrypted file.")

    def remove_files_toggle_button_clicked(self):
        """Handle the click event of the toggle remove files after encryption and decryption button"""
        current_state = self.remove_files_toggle_button.text()
        if current_state == "Remove files after encryption/decryption \U0001F5D1 : \u274C (Disabled)":
            self.remove_files_toggle_button.setText("Remove files after encryption/decryption \U0001F5D1 : \u2705 (Enabled)")
        else:
            self.remove_files_toggle_button.setText("Remove files after encryption/decryption \U0001F5D1 : \u274C (Disabled)")
    
    def toggle_show_progress_bar_clicked(self):
        """Handle the click event of the show progress bar button."""
        current_state = self.toggle_show_progress_bar.text()
        if current_state == "Show encryption/decryption progress : \u2705 (Enabled)":
            self.toggle_show_progress_bar.setText("Show encryption/decryption progress : \u274C (Disabled)")
        else:
            self.toggle_show_progress_bar.setText("Show encryption/decryption progress : \u2705 (Enabled)")

    def encrypt_button_click(self):
        """Handle encrypt button click event"""
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

        # Set default argument value
        separate_iv_key=False
        recovery_key=False
        remove_encrypted_files=False
        show_progress=True

        # Change arguments value to user's preferrence
        if self.gen_iv_key_button.text() == "Generate key file \U0001F511 : \u2705 (Enabled)":
            separate_iv_key=True
        if self.gen_recovery_key_button.text() == "Generate recovery key \U0001F510 : \u2705 (Enabled)":
            recovery_key=True
        if self.remove_files_toggle_button.text() == "Remove files after encryption/decryption \U0001F5D1 : \u2705 (Enabled)":
            remove_encrypted_files=True
        if self.toggle_show_progress_bar.text() == "Show encryption/decryption progress : \u274C (Disabled)":
            show_progress=False

        # Starts the main encryption process
        iv = get_random_bytes(16)
        iv_hash = hashlib.sha1(iv).digest()
        key = hashlib.sha256(password.encode()).digest()
        block_size = get_optimal_block_size()

        # Determine file paths and names based on whether it's a file or directory
        if os.path.isdir(file_path):
            try:
                compressed_file_path = generate_unique_file_name(file_path, add_extension=".temp")
                compressed_files = self.compress_directory(file_path, compressed_file_path)
                encrypted_file_path = generate_unique_file_name(file_path)
                file_to_encrypt = compressed_file_path
            except ValueError as ve:
                QMessageBox.critical(self, "ValueError", f"An error occurred during encryption: {str(ve)}")
                return
            except Exception as e:
                QMessageBox.critical(self, "Unhandled Exception Error", f"An error occurred during encryption: {str(e)}")
                return

        elif os.path.isfile(file_path):
            encrypted_file_path = generate_unique_file_name(file_path)
            file_to_encrypt = file_path

        # Check if the encrypted file path can be determined
        if encrypted_file_path is None:
            raise ValueError("An error occurred during encryption: Could not determine the encrypted file path, please try renaming the file before trying again.")

        QMessageBox.warning(self, "Warning Note", "Initiating encryption process. Please refrain from interacting with the app window until encryption is complete to prevent potential freezing. While the encryption will continue unaffected, the window will only become responsive once the process is finished or if an error arises.")

        try:
            # Create the encrypted file
            with open(encrypted_file_path, "wb") as encrypted_file:
                file_size = os.path.getsize(file_to_encrypt)
                total_tasks = file_size
                completed_tasks = 0

                # Write IV to the encrypted file or a separate IV key file
                if not separate_iv_key:
                    encrypted_file.write(iv)
                else:
                    iv_key_file = f"{file_to_encrypt}.ivkey" if not os.path.exists(f"{file_to_encrypt}.ivkey") \
                        else generate_unique_key_file_name(file_to_encrypt, add_extension=".ivkey")

                    with open(iv_key_file, "wb") as key_file:
                        key_file.write(iv)

                # Encrypt the file
                with open(file_to_encrypt, "rb") as file:
                    cipher = AES.new(key, AES.MODE_EAX, iv)
                    while True:
                        chunk = file.read(block_size)
                        if not chunk:
                            break
                        encrypted_chunk = cipher.encrypt(chunk)
                        encrypted_file.write(encrypted_chunk)
                        completed_tasks += len(chunk)
                        completed_percent = (completed_tasks / total_tasks) * 100
                        if show_progress:
                            self.progress_bar.setValue(int(completed_percent))

                # Write IV hash to the encrypted file
                encrypted_file.write(iv_hash)

                # Remove the original files if specified
                if remove_encrypted_files:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        for file in compressed_files:
                            os.remove(file)
                        for root, dirs, files in os.walk(file_path, topdown=False):
                            for dir in dirs:
                                dir_path = os.path.join(root, dir)
                                if not os.listdir(dir_path):
                                    os.rmdir(dir_path)

            # Generate a recovery key file if specified
            if recovery_key:
                keyfile = generate_unique_key_file_name(file_to_encrypt, add_extension=".rkey")
                hashkey = hashlib.sha256(password.encode()).hexdigest()
                with open(keyfile, "w") as file:
                    file.write(hashkey)

            # Remove the temporary compressed file if encrypting a directory
            if os.path.isdir(file_path):
                os.remove(compressed_file_path)
            
            QMessageBox.information(self, "Encryption Successful", "Encryption process completed successfully.")
            self.progress_bar.setValue(0)

        except Exception as e:
            QMessageBox.critical(self, "Unhandled Exception Error", f"An error occurred during encryption: {str(e)}")
            self.progress_bar.setValue(0)

    def decrypt_button_click(self):
        """Handle decrypt button click event"""
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
        remove_encrypted_files = False
        show_progress=True

        # Change arguments value to user's preferrence
        if not iv_key_file.strip() == "":
            separate_iv_key = iv_key_file.strip()
        if not recovery_key_file.strip() == "":
            hash_password = False
            with open(recovery_key_file.strip(), 'r') as file:
                password = file.read(64)
        if self.remove_files_toggle_button.text() == "Remove files after encryption/decryption \U0001F5D1 : \u2705 (Enabled)":
            remove_encrypted_files = True
        if self.toggle_show_progress_bar.text() == "Show encryption/decryption progress : \u274C (Disabled)":
            show_progress=False
        
        # Starts the main decryption process
        block_size = get_optimal_block_size()

        if hash_password:
            key = hashlib.sha256(password.encode()).digest()
        else:
            key = bytes.fromhex(password)

        if os.path.isdir(file_path):
            file_name = os.path.basename(file_path)
            file_to_decrypt = os.path.join(file_path, file_name + ".pack")
        elif os.path.isfile(file_path):
            file_to_decrypt = file_path
        else:
            QMessageBox.critical(self, "ValueError", "An error occurred during decryption: Invalid file or folder name.")
            return
        
        QMessageBox.warning(self, "Warning Note", "Initiating decryption process. Please refrain from interacting with the app window until decryption is complete to prevent potential freezing. While the decryption will continue unaffected, the window will only become responsive once the process is finished or if an error arises.")

        if separate_iv_key == None:
            if os.path.getsize(file_to_decrypt) < 36:
                QMessageBox.critical(self, "ValueError", "An error occurred during decryption: Encrypted file size must be higher then 36 bytes.")
                return
            with open(file_to_decrypt, "rb") as file:
                iv = file.read(16)
                file.seek(-20, os.SEEK_END)
                expected_iv_hash = file.read()
        elif separate_iv_key != '' and not separate_iv_key == None:
            if not os.path.exists(separate_iv_key):
                QMessageBox.critical(self, "ValueError", "An error occurred during decryption: Invalid key file path.")
                return
            else:
                if os.path.getsize(separate_iv_key) < 16:
                    QMessageBox.critical(self, "ValueError", "An error occurred during decryption: Invalid or corrupted key file.")
                    return
                try:
                    with open(separate_iv_key, "rb") as ivkey_file:
                        iv = ivkey_file.read(16)
                    with open(file_to_decrypt, "rb") as file:
                        file.seek(-20, os.SEEK_END)
                        expected_iv_hash = file.read()
                except Exception as e:
                    QMessageBox.critical(self, "Unhandled Exception Error", f"An error occurred during decryption: {str(e)}")
                    return

        iv_hash = hashlib.sha1(iv).digest()
        if iv_hash != expected_iv_hash:
            QMessageBox.critical(self, "File Error", "An error occurred during decryption: Invalid file. The IV key does not match the expected hash.")
            return

        if separate_iv_key is not None:
            if os.path.getsize(file_to_decrypt) < 20:
                QMessageBox.critical(self, "File Error", "An error occurred during decryption: Encrypted file size must be higher then 20 bytes.")
                return

        encrypted_file_dir = os.path.dirname(file_to_decrypt)
        base_file_name = os.path.basename(file_to_decrypt)
        if base_file_name.endswith(".pack"):
            base_file_name = os.path.splitext(os.path.basename(base_file_name))[0]
        extraction_dir = os.path.join(encrypted_file_dir, base_file_name + "_unpacked")

        while os.path.exists(extraction_dir):
            extraction_dir = os.path.join(
                encrypted_file_dir, base_file_name + "_unpacked;" + generate_random_string(5)
            )
        os.makedirs(extraction_dir)

        if file_to_decrypt.endswith(".pack"):
            decrypted_file_name = os.path.splitext(os.path.basename(file_to_decrypt))[0]
        else:
            decrypted_file_name = file_to_decrypt
        
        decrypted_file_path = os.path.join(extraction_dir, decrypted_file_name)

        try:
            with open(decrypted_file_path, "wb") as decrypted_file:
                if separate_iv_key is None:
                    file_size = os.path.getsize(file_to_decrypt) - 36
                elif separate_iv_key is not None:
                    file_size = os.path.getsize(file_to_decrypt) - 20

                total_tasks = file_size
                completed_tasks = 0

                with open(file_to_decrypt, "rb") as file:
                    if separate_iv_key is None:
                        file.seek(16)
                    encrypted_data = file.read()[:-20]
                    cipher = AES.new(key, AES.MODE_EAX, iv)

                    decrypted_data = b""
                    offset = 0
                    while offset < len(encrypted_data):
                        chunk = encrypted_data[offset:offset + block_size]
                        decrypted_chunk = cipher.decrypt(chunk)
                        decrypted_file.write(decrypted_chunk)
                        decrypted_data += decrypted_chunk
                        offset += block_size
                        completed_tasks += len(decrypted_chunk)
                        completed_percent = (completed_tasks / total_tasks) * 100
                        if show_progress:
                            self.progress_bar.setValue(int(completed_percent))

            if tarfile.is_tarfile(decrypted_file_path):
                with tarfile.open(decrypted_file_path, "r") as tar_ref:
                    files_list = [member.name for member in tar_ref.getmembers() if not member.isdir()]
                
                if "~encrypto_pack" in files_list:
                    with tarfile.open(decrypted_file_path, "r") as tar_ref:
                        tar_ref.extractall(extraction_dir)
                    
                    os.remove(os.path.join(extraction_dir, "~encrypto_pack"))
                    os.remove(decrypted_file_path)
                
            if remove_encrypted_files:
                os.remove(file_to_decrypt)
            
            QMessageBox.information(self, "Decryption Successful", "Decryption process completed successfully.")
            self.progress_bar.setValue(0)

        except Exception as e:
            QMessageBox.critical(self, "Unhandled Exception Error", f"An error occurred during decryption: {str(e)}")
            self.progress_bar.setValue(0)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()

    main_window.activateWindow() # Give the main window focus
    main_window.raise_() # Bring the main window to the front

    sys.exit(app.exec_())
