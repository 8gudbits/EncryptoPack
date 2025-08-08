from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication


class UITheme:
    """Provides theme management and styling for the application UI.

    Contains static methods for:
    - Detecting system dark mode
    - Generating color palettes
    - Providing styled components
    """
    @staticmethod
    def is_dark_mode() -> bool:
        """Determines if the system is using a dark theme.

        Returns:
            bool: True if dark mode is active, False otherwise
        """
        palette = QApplication.palette()
        window_color = palette.color(QPalette.ColorRole.Window)
        return window_color.value() < 128

    @staticmethod
    def get_color_palette():
        if UITheme.is_dark_mode():
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
            return dark_palette
        else:
            light_palette = QPalette()
            light_palette.setColor(QPalette.ColorRole.Window, Qt.GlobalColor.white)
            light_palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
            light_palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
            light_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(240, 240, 240))
            light_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
            light_palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.black)
            light_palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.black)
            light_palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            light_palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            light_palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
            light_palette.setColor(QPalette.ColorRole.Link, QColor(0, 120, 215))
            light_palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 215))
            light_palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
            return light_palette

    @staticmethod
    def get_stylesheet():
        """Generates a QPalette based on current system theme.

        Returns:
            QPalette: Color palette matching system dark/light mode
        """
        if UITheme.is_dark_mode():
            bg_color = "#2e2e2e"
            sel_bg_color = "#3d3d3d"
            sel_color = "white"
            border_color = "#4a4a4a"
            text_color = "white"
        else:
            bg_color = "#f5f5f5"
            sel_bg_color = "#cce4ff"
            sel_color = "black"
            border_color = "#cccccc"
            text_color = "black"
        return f"""
            QWidget {{
                font-size: 9pt;
                font-family: 'Segoe UI Emoji', 'Segoe UI', Arial;
            }}
            QComboBox {{
                background-color: {bg_color};
                color: {text_color};
                selection-background-color: {sel_bg_color};
                border: 1px solid {border_color};
                border-radius: 4px;
                padding: 2px 2px 2px 4px;
            }}
            QComboBox:!editable {{
                color: {text_color};
            }}
            QComboBox QAbstractItemView {{
                background-color: {bg_color};
                color: {text_color};
                selection-background-color: {sel_bg_color};
                selection-color: {sel_color};
            }}
            QLineEdit {{
                background-color: {bg_color};
                color: {text_color};
                selection-background-color: {sel_bg_color};
                border: 1px solid {border_color};
                border-radius: 4px;
                padding: 2px 6px;
            }}
        """

    @staticmethod
    def get_placeholder_lineedit_style():
        """Provides styling for placeholder text input fields.

        Returns:
            str: CSS-style string for QLineEdit
        """
        if UITheme.is_dark_mode():
            bg_color = "#2e2e2e"
            sel_bg_color = "#3d3d3d"
            text_color = "white"
        else:
            bg_color = "#f5f5f5"
            sel_bg_color = "#cce4ff"
            text_color = "black"
        return f"""
            QLineEdit {{
                background-color: {bg_color};
                color: {text_color};
                border: none;
                border-bottom: 1px solid transparent;
                selection-background-color: {sel_bg_color};
                border-radius: 4px;
                padding: 2px 6px;
            }}
            QLineEdit:focus {{
                border-bottom: 1px solid #d2691e;
            }}
        """

    @staticmethod
    def get_section_label_style():
        """Provides styling for section header labels.

        Returns:
            str: CSS-style string for section headers
        """
        if UITheme.is_dark_mode():
            border_color = "#3d3d3d"
        else:
            border_color = "#cccccc"
        return f"""
            QLabel {{
                color: #d2691e;
                font-weight: bold;
                background-color: transparent;
                border-bottom: 1px solid {border_color};
                padding: 0 0 2px 0;
            }}
        """

    @staticmethod
    def get_styled_button_style():
        """Provides base styling for standard buttons.

        Returns:
            str: CSS-style string for QPushButton elements
        """
        if UITheme.is_dark_mode():
            bg_normal = "#4a4a4a"
            bg_hover = "#5a5a5a"
            bg_pressed = "#3a3a3a"
            bg_disabled = "#888888"
            text_normal = "white"
            text_disabled = "#cccccc"
        else:
            bg_normal = "#e0e0e0"
            bg_hover = "#d5d5d5"
            bg_pressed = "#c0c0c0"
            bg_disabled = "#f0f0f0"
            text_normal = "black"
            text_disabled = "#888888"
        return f"""
            QPushButton {{
                background-color: {bg_normal};
                color: {text_normal};
                border: none;
                border-radius: 4px;
                padding: 4px;
            }}
            QPushButton:hover {{
                background-color: {bg_hover};
            }}
            QPushButton:pressed {{
                background-color: {bg_pressed};
            }}
            QPushButton:disabled {{
                background-color: {bg_disabled};
                color: {text_disabled};
            }}
        """

    @staticmethod
    def get_progress_bar_style():
        """Provides styling for progress bars.

        Returns:
            str: CSS-style string for QProgressBar elements
        """
        if UITheme.is_dark_mode():
            bg = "#252525"
            text_color = "white"
        else:
            bg = "#f0f0f0"
            text_color = "black"
        return f"""
            QProgressBar {{
                border: none;
                background-color: {bg};
                color: {text_color};
                border-radius: 4px;
                text-align: center;
                height: 10px;
            }}
            QProgressBar::chunk {{
                background-color: #d2691e;
                border-radius: 4px;
            }}
        """

    @staticmethod
    def get_encrypt_button_style():
        """Provides styling for encryption buttons.

        Returns:
            str: CSS-style string for encryption action buttons
        """
        if UITheme.is_dark_mode():
            bg_normal = "#4a6741"
            bg_hover = "#5a7a50"
            bg_pressed = "#3a5732"
            text_normal = "white"
        else:
            bg_normal = "#28a745"
            bg_hover = "#34b759"
            bg_pressed = "#1e7e34"
            text_normal = "white"
        return f"""
            QPushButton {{
                background-color: {bg_normal};
                color: {text_normal};
                border: none;
                border-radius: 4px;
                padding: 4px;
            }}
            QPushButton:hover {{
                background-color: {bg_hover};
            }}
            QPushButton:pressed {{
                background-color: {bg_pressed};
            }}
            QPushButton:disabled {{
                background-color: #888888;
                color: #cccccc;
            }}
        """

    @staticmethod
    def get_decrypt_button_style():
        """Provides styling for decryption buttons.

        Returns:
            str: CSS-style string for decryption action buttons
        """
        if UITheme.is_dark_mode():
            bg_normal = "#5e3d50"
            bg_hover = "#754964"
            bg_pressed = "#4a2d3c"
            text_normal = "white"
        else:
            bg_normal = "#e83e8c"
            bg_hover = "#f061a2"
            bg_pressed = "#c72f73"
            text_normal = "white"
        return f"""
            QPushButton {{
                background-color: {bg_normal};
                color: {text_normal};
                border: none;
                border-radius: 4px;
                padding: 4px;
            }}
            QPushButton:hover {{
                background-color: {bg_hover};
            }}
            QPushButton:pressed {{
                background-color: {bg_pressed};
            }}
            QPushButton:disabled {{
                background-color: #888888;
                color: #cccccc;
            }}
        """

