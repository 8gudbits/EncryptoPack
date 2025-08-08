from PyQt6.QtWidgets import QApplication
from gui import MainWindow

import sys


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Check for file path argument
    file_path = None
    if len(sys.argv) > 1:
        file_path = sys.argv[1]

    main_window = MainWindow(file_path)
    main_window.show()
    main_window.activateWindow()
    main_window.raise_()
    sys.exit(app.exec())

