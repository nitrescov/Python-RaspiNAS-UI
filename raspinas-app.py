import os
import sys
import json
import socket
import hashlib
from PySide6 import QtCore, QtWidgets, QtGui

from locales import locales
from protocol import *


class MainWindow(QtWidgets.QMainWindow):
    # This window is initialized first; If a valid config file is found and the login credentials were saved,
    # it will try to establish a connection immediately; Otherwise the settings window will be opened first

    def __init__(self):
        super().__init__()

        # Initialize the central widget
        self.main_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(self.main_widget)

        self.s_layout = QtWidgets.QVBoxLayout()
        s_scrollable = QtWidgets.QScrollArea()
        s_widget = QtWidgets.QWidget()
        s_widget.setLayout(self.s_layout)
        s_scrollable.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        s_scrollable.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        s_scrollable.setWidgetResizable(True)
        s_scrollable.setWidget(s_widget)

        self.l_error = QtWidgets.QLabel("Error")
        self.l_error.setStyleSheet("color: red; font: bold;")
        self.l_error.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.p_progress = QtWidgets.QProgressBar()
        self.p_progress.setRange(0, 1000)
        self.p_progress.setValue(0)
        self.p_progress.hide()

        self.b_upload = QtWidgets.QPushButton("Upload file")
        self.b_upload.clicked.connect(self.upload_file)
        self.b_upload.setEnabled(False)
        self.b_download = QtWidgets.QPushButton("Download directory")
        self.b_download.clicked.connect(self.download_directory)
        self.b_download.setEnabled(False)
        self.b_settings = QtWidgets.QPushButton("Settings")
        self.b_settings.clicked.connect(self.show_settings)
        buttons_layout = QtWidgets.QHBoxLayout()
        buttons_layout.addWidget(self.b_upload)
        buttons_layout.addWidget(self.b_download)
        buttons_layout.addWidget(self.b_settings)

        main_layout = QtWidgets.QVBoxLayout(self.main_widget)
        main_layout.setSpacing(20)
        main_layout.addWidget(s_scrollable)
        main_layout.addLayout(buttons_layout)
        main_layout.addWidget(self.p_progress)
        main_layout.addWidget(self.l_error)

        # Setup state variables
        self.hash = None
        self.connection = None
        self.settings_window = None
        self.selected_button = None
        self.selected_path = str()

        # Load the existing configuration, if any
        self.config_location = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
        self.config = {"language": str(), "ip": str(), "port": int(), "username": str(), "hash": None}
        self.load_config()

        if self.config["language"] not in locales["languages"].values():
            self.config["language"] = "en"

        # If no config file exists or login credentials were not saved, open the settings window
        if not self.config["username"] or self.config["hash"] is None:
            self.settings_window = SettingsWindow(self)
        else:
            self.hash = self.config["hash"]
            self.establish_connection()

    @QtCore.Slot()
    def show_settings(self):
        self.connection.close()
        self.clear_scroll_layout()
        self.settings_window = SettingsWindow(self)

    @QtCore.Slot()
    def upload_file(self):
        self.l_error.setText("")
        self.p_progress.setValue(0)
        self.p_progress.show()
        self.b_upload.setEnabled(False)
        self.b_download.setEnabled(False)
        self.b_settings.setEnabled(False)
        current_path = self.selected_path
        try:
            if not current_path:
                raise InternalError("error-select-dir")
            source = QtWidgets.QFileDialog.getOpenFileName(self,
                                                           locales[self.config["language"]]["choose-upload"],
                                                           os.path.expanduser("~"),
                                                           (locales[self.config["language"]]["zip-archive"] + ";;" +
                                                            locales[self.config["language"]]["all-files"]))
            if not source[0]:
                raise InternalError("nothing-chosen-error")
            if not os.path.isfile(source[0]):
                raise InternalError("file-not-exists-error")
            pkt_content = SEPARATOR.join([os.path.basename(source[0]), current_path]).encode("utf-8")
            for counter in range(RETRY_COUNT):
                send_header(self.connection, len(pkt_content), CMD_UPLOAD_FILE, TYPE_DATA, calc_hash(pkt_content))
                self.connection.sendall(pkt_content)
                if receive_check_response(self.connection, CMD_UPLOAD_FILE):
                    break
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")
            for counter in range(RETRY_COUNT):
                pkt_len, pkt_cmd, pkt_type, pkt_checksum = receive_header(self.connection)
                if pkt_len != 0 or pkt_cmd != RSP_UPLOAD_FILE:
                    raise ValueError("Invalid response command, next packet size cannot be determined")
                if pkt_type == TYPE_FAILURE:
                    send_check_response(self.connection, RSP_UPLOAD_FILE, CHECK_VALID)
                    raise InternalError("file-upload-error")
                elif pkt_type == TYPE_SUCCESS:
                    send_check_response(self.connection, RSP_UPLOAD_FILE, CHECK_VALID)
                    break
                else:
                    raise ValueError("Invalid response data type, next packet type cannot be determined")
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")

            # Server accepts the file, send it in an additional data package
            for counter in range(RETRY_COUNT):
                file_size = os.path.getsize(source[0])
                send_header(self.connection, file_size, CDT_UPLOAD_FILE, TYPE_FILE, calc_hash(source[0]))
                with open(source[0], "rb") as send_file:
                    current_size = 0
                    while True:
                        raw_data = send_file.read(BUFFER)
                        if not raw_data:
                            break
                        self.connection.sendall(raw_data)
                        current_size += len(raw_data)
                        self.p_progress.setValue(int((current_size / file_size) * 1000))
                if receive_check_response(self.connection, CDT_UPLOAD_FILE):
                    break
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")
            for counter in range(RETRY_COUNT):
                pkt_len, pkt_cmd, pkt_type, pkt_checksum = receive_header(self.connection)
                if pkt_len > 0:
                    raise ValueError("Invalid data waiting in receiving pipe")
                if pkt_cmd == RDT_UPLOAD_FILE and pkt_type == TYPE_SUCCESS:
                    send_check_response(self.connection, RDT_UPLOAD_FILE, CHECK_VALID)
                    self.l_error.setStyleSheet("font: bold;")
                    self.l_error.setText(locales[self.config["language"]]["upload-success"])
                    break
                else:
                    send_check_response(self.connection, RDT_UPLOAD_FILE, CHECK_VALID)
                    raise InternalError("file-processing-error")
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")

            self.b_upload.setEnabled(True)
            self.b_download.setEnabled(True)
        except InternalError as e:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]][str(e)])
            self.b_upload.setEnabled(True)
            self.b_download.setEnabled(True)
        except ConnectionError:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["connection-error"])
            self.connection.close()
        except Exception as e:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["fatal-error"] + str(e))
            self.connection.close()
        finally:
            self.p_progress.hide()
            self.b_settings.setEnabled(True)

    @QtCore.Slot()
    def download_directory(self):
        self.l_error.setText("")
        self.p_progress.setValue(0)
        self.p_progress.show()
        self.b_upload.setEnabled(False)
        self.b_download.setEnabled(False)
        self.b_settings.setEnabled(False)
        current_path = self.selected_path
        try:
            if not current_path:
                raise InternalError("error-select-dir")
            target = QtWidgets.QFileDialog.getSaveFileName(self,
                                                           locales[self.config["language"]]["choose-download"],
                                                           os.path.expanduser("~"),
                                                           locales[self.config["language"]]["zip-archive"])
            if not target[0]:
                raise InternalError("nothing-chosen-error")
            target_path = target[0] if target[0].split(".")[-1].lower() == "zip" else target[0] + ".zip"
            pkt_content = current_path.encode("utf-8")
            for counter in range(RETRY_COUNT):
                send_header(self.connection, len(pkt_content), CMD_DOWNLOAD_FOLDER, TYPE_DATA, calc_hash(pkt_content))
                self.connection.sendall(pkt_content)
                if receive_check_response(self.connection, CMD_DOWNLOAD_FOLDER):
                    break
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")
            for counter in range(RETRY_COUNT):
                pkt_len, pkt_cmd, pkt_type, pkt_checksum = receive_header(self.connection)
                if pkt_cmd != RSP_DOWNLOAD_FOLDER:
                    raise ValueError("Invalid response command, next packet size cannot be determined")
                if pkt_type == TYPE_FAILURE and pkt_len == 0:
                    send_check_response(self.connection, RSP_DOWNLOAD_FOLDER, CHECK_VALID)
                    raise InternalError("file-error")
                elif pkt_type == TYPE_FILE and pkt_len > 0:
                    with open(target_path, "wb") as new_file:
                        remaining_len = pkt_len
                        while remaining_len > 0:
                            raw_data = self.connection.recv(min(BUFFER, remaining_len))
                            if not raw_data:
                                raise ConnectionError()
                            new_file.write(raw_data)
                            remaining_len -= len(raw_data)
                            self.p_progress.setValue(int((1 - (remaining_len / pkt_len)) * 1000))
                    if calc_hash(target_path) == pkt_checksum:
                        send_check_response(self.connection, RSP_DOWNLOAD_FOLDER, CHECK_VALID)
                        self.l_error.setStyleSheet("font: bold;")
                        self.l_error.setText(locales[self.config["language"]]["download-success"])
                        break
                    else:
                        send_check_response(self.connection, RSP_DOWNLOAD_FOLDER, CHECK_INVALID)
                        continue
                else:
                    raise ValueError("Invalid response data type, next packet type cannot be determined")
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")

            self.b_upload.setEnabled(True)
            self.b_download.setEnabled(True)
        except InternalError as e:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]][str(e)])
            self.b_upload.setEnabled(True)
            self.b_download.setEnabled(True)
        except ConnectionError:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["connection-error"])
            self.connection.close()
        except Exception as e:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["fatal-error"] + str(e))
            self.connection.close()
        finally:
            self.p_progress.hide()
            self.b_settings.setEnabled(True)

    def load_config(self):
        try:
            with open(self.config_location, "r") as config_file:
                cnf = json.load(config_file)
            # Copy the values separately to ensure all necessary keys are present
            self.config["language"] = str(cnf["language"])
            self.config["ip"] = str(cnf["ip"])
            self.config["port"] = int(cnf["port"])
            self.config["username"] = str(cnf["username"])
            self.config["hash"] = None if cnf["hash"] is None else str(cnf["hash"])
        except FileNotFoundError:
            # A new config file will be created later
            return
        except (ValueError, KeyError):
            error = QtWidgets.QMessageBox(self)
            error.setWindowTitle(locales["en"]["config-error-title"])
            error.setText(locales["en"]["config-error"])
            error.exec()
            sys.exit(-1)
        except PermissionError:
            error = QtWidgets.QMessageBox(self)
            error.setWindowTitle(locales["en"]["permission-error-title"])
            error.setText(locales["en"]["permission-error"])
            error.exec()
            sys.exit(-1)

    def change_language(self, lang: str):
        self.b_upload.setText(locales[lang]["upload"])
        self.b_download.setText(locales[lang]["download"])
        self.b_settings.setText(locales[lang]["settings"])
        self.l_error.setStyleSheet("font: bold;")
        self.l_error.setText(locales[lang]["info-select-dir"])

    def establish_connection(self):
        # Change language here after configuration is loaded / modified
        self.change_language(self.config["language"])

        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.resize(1000, 600)
        self.show()

        try:
            # Login procedure
            self.connection.connect((self.config["ip"], self.config["port"]))
            login_packet = SEPARATOR.join([self.config["username"], self.hash]).encode("utf-8")
            for counter in range(RETRY_COUNT):
                send_header(self.connection, len(login_packet), CMD_LOGIN, TYPE_DATA, calc_hash(login_packet))
                self.connection.sendall(login_packet)
                if receive_check_response(self.connection, CMD_LOGIN):
                    break
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")
            for counter in range(RETRY_COUNT):
                pkt_len, pkt_cmd, pkt_type, pkt_checksum = receive_header(self.connection)
                if pkt_cmd != RSP_LOGIN or pkt_len != 0:
                    raise InternalError("data-error")
                else:
                    send_check_response(self.connection, RSP_LOGIN, CHECK_VALID)
                    break
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")
            if pkt_type == TYPE_FAILURE:
                raise InternalError("login-error")
            if pkt_type != TYPE_SUCCESS:
                raise InternalError("data-error")

            # Directory refresh procedure
            for counter in range(RETRY_COUNT):
                send_header(self.connection, 0, CMD_GET_DIRECTORIES, TYPE_NONE, bytes(48))
                if receive_check_response(self.connection, CMD_GET_DIRECTORIES):
                    break
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")
            for counter in range(RETRY_COUNT):
                pkt_len, pkt_cmd, pkt_type, pkt_checksum = receive_header(self.connection)
                if pkt_cmd != RSP_GET_DIRECTORIES or pkt_type != TYPE_DATA or pkt_len < 1:
                    raise InternalError("get-dir-error")
                pkt_content = recvall(self.connection, pkt_len)
                if calc_hash(pkt_content) == pkt_checksum:
                    send_check_response(self.connection, RSP_GET_DIRECTORIES, CHECK_VALID)
                    break
                else:
                    send_check_response(self.connection, RSP_GET_DIRECTORIES, CHECK_INVALID)
                    continue
            if counter >= (RETRY_COUNT - 1):
                raise InternalError("retry-error")
            folders = pkt_content.decode("utf-8").split(SEPARATOR)
            for f in folders:
                b = GenericSelectorButton(self, f)
                self.s_layout.addWidget(b)
            self.s_layout.addStretch()

            # Finally, activate the Upload / Download buttons
            self.b_upload.setEnabled(True)
            self.b_download.setEnabled(True)
        except InternalError as e:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]][str(e)])
            self.connection.close()
        except ConnectionRefusedError:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["connection-refused-error"])
            self.connection.close()
        except ConnectionError:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["connection-error"])
            self.connection.close()
        except TimeoutError:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["timeout-error"])
            self.connection.close()
        except Exception as e:
            self.l_error.setStyleSheet("color: red; font: bold;")
            self.l_error.setText(locales[self.config["language"]]["fatal-error"] + str(e))
            self.connection.close()

    def clear_scroll_layout(self):
        self.selected_button = None
        self.selected_path = str()
        while self.s_layout.count():
            element = self.s_layout.takeAt(0)
            if element.widget():
                element.widget().deleteLater()

    def closeEvent(self, event: QtGui.QCloseEvent):
        # Alternative to kill the whole app: sys.exit(0); Prevent closing: event.ignore()
        try:
            self.connection.close()
        except AttributeError:
            # No connection established yet
            pass
        event.accept()


class SettingsWindow(QtWidgets.QMainWindow):
    # This window is opened if no valid configuration can be found or the user wants to change the settings

    def __init__(self, parent: MainWindow):
        super().__init__(parent=parent)

        self.parent = parent
        self.setWindowTitle("RaspiNAS-App - Settings")

        # Initialize the central widget
        settings_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(settings_widget)

        self.l_settings = QtWidgets.QLabel("Settings")
        self.l_settings.setStyleSheet("font: bold 20px;")

        self.g_general = QtWidgets.QGroupBox("General")
        self.l_language = QtWidgets.QLabel("Language:")
        self.d_language = QtWidgets.QComboBox()
        self.d_language.addItems(locales["languages"].keys())
        self.d_language.textActivated.connect(self.change_language)
        self.l_ip = QtWidgets.QLabel("Server IP address:")
        self.e_ip = QtWidgets.QLineEdit()
        self.e_ip.setPlaceholderText("192.168.1.42")
        self.l_port = QtWidgets.QLabel("Server port:")
        self.e_port = QtWidgets.QLineEdit()
        self.e_port.setPlaceholderText("5001")
        general_layout = QtWidgets.QGridLayout(self.g_general)
        general_layout.setHorizontalSpacing(20)
        general_layout.addWidget(self.l_language, 0, 0)
        general_layout.addWidget(self.d_language, 0, 1)
        general_layout.addWidget(self.l_ip, 1, 0)
        general_layout.addWidget(self.e_ip, 1, 1)
        general_layout.addWidget(self.l_port, 2, 0)
        general_layout.addWidget(self.e_port, 2, 1)
        
        self.g_credentials = QtWidgets.QGroupBox("Login credentials")
        self.l_name = QtWidgets.QLabel("Username:")
        self.e_name = QtWidgets.QLineEdit()
        self.l_password = QtWidgets.QLabel("Password:")
        self.e_password = QtWidgets.QLineEdit()
        self.e_password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.c_save_creds = QtWidgets.QCheckBox("Save login credentials?")
        credentials_layout = QtWidgets.QGridLayout(self.g_credentials)
        credentials_layout.setHorizontalSpacing(20)
        credentials_layout.addWidget(self.l_name, 0, 0)
        credentials_layout.addWidget(self.e_name, 0, 1)
        credentials_layout.addWidget(self.l_password, 1, 0)
        credentials_layout.addWidget(self.e_password, 1, 1)
        credentials_layout.addWidget(self.c_save_creds, 2, 1)

        self.b_discard = QtWidgets.QPushButton("Discard and exit")
        self.b_discard.clicked.connect(self.close)
        self.b_save = QtWidgets.QPushButton("Save and continue")
        self.b_save.clicked.connect(self.save_config)
        buttons_layout = QtWidgets.QHBoxLayout()
        buttons_layout.addWidget(self.b_discard)
        buttons_layout.addWidget(self.b_save)

        settings_layout = QtWidgets.QVBoxLayout(settings_widget)
        settings_layout.setSpacing(20)
        settings_layout.addWidget(self.l_settings)
        settings_layout.addWidget(self.g_general)
        settings_layout.addWidget(self.g_credentials)
        settings_layout.addLayout(buttons_layout)
        settings_layout.addStretch()

        # Set previously configured values as defaults
        language = list(locales["languages"].keys())[
            list(locales["languages"].values()).index(self.parent.config["language"])
        ]
        self.d_language.setCurrentText(language)
        self.change_language(language)
        if self.parent.config["ip"]:
            self.e_ip.setText(str(self.parent.config["ip"]))
        if self.parent.config["port"]:
            self.e_port.setText(str(self.parent.config["port"]))
        if self.parent.config["username"]:
            self.e_name.setText(str(self.parent.config["username"]))

        self.parent.main_widget.setEnabled(False)
        self.show()

    @QtCore.Slot()
    def save_config(self):
        language = locales["languages"][self.d_language.currentText()]
        try:
            self.parent.hash = hashlib.sha384(
                self.e_password.text().encode("utf-8") + self.e_name.text().encode("utf-8")
            ).hexdigest()
            self.parent.config["language"] = language
            self.parent.config["ip"] = self.e_ip.text()
            self.parent.config["port"] = int(self.e_port.text())
            self.parent.config["username"] = self.e_name.text()
            self.parent.config["hash"] = self.parent.hash if self.c_save_creds.isChecked() else None
            with open(self.parent.config_location, "w") as config_file:
                json.dump(self.parent.config, config_file, indent=2)
            # If saving the configuration was successful, exit this window and start connection in the main window
            self.close()
        except (ValueError, UnicodeEncodeError):
            error = QtWidgets.QMessageBox(self)
            error.setWindowTitle(locales[language]["value-error-title"])
            error.setText(locales[language]["value-error"])
            error.exec()
        except PermissionError:
            error = QtWidgets.QMessageBox(self)
            error.setWindowTitle(locales[language]["permission-error-title"])
            error.setText(locales[language]["permission-error"])
            error.exec()
            sys.exit(-1)

    @QtCore.Slot(str)
    def change_language(self, lang: str):
        language = locales["languages"][lang]
        self.setWindowTitle("RaspiNAS-App - " + locales[language]["settings"])
        self.l_settings.setText(locales[language]["settings"])
        self.g_general.setTitle(locales[language]["general"])
        self.l_language.setText(locales[language]["language"])
        self.l_ip.setText(locales[language]["ip-address"])
        self.l_port.setText(locales[language]["port"])
        self.g_credentials.setTitle(locales[language]["credentials"])
        self.l_name.setText(locales[language]["username"])
        self.l_password.setText(locales[language]["password"])
        self.c_save_creds.setText(locales[language]["save-credentials"])
        self.b_discard.setText(locales[language]["discard"])
        self.b_save.setText(locales[language]["save"])
        # Enable immediate switching between languages in both windows (this does not reset when discarding settings!)
        # self.parent.change_language(language)

    def closeEvent(self, event: QtGui.QCloseEvent):
        if self.isVisible():
            self.parent.main_widget.setEnabled(True)
            self.parent.establish_connection()
        event.accept()


class GenericSelectorButton(QtWidgets.QPushButton):
    def __init__(self, reference: MainWindow, text=str(), parent=None):
        super().__init__(text=text, parent=parent)

        @QtCore.Slot()
        def on_click():
            if reference.selected_button is not None:
                reference.selected_button.setChecked(False)
            self.setChecked(True)
            reference.selected_button = self
            reference.selected_path = text

        self.setCheckable(True)
        self.setStyleSheet("text-align: left; padding: 2px; padding-left: 6px;")
        self.clicked.connect(on_click)
        self.setText(text if len(text) <= 80 else ("..." + text[-77:]))


class InternalError(Exception):
    pass


if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    app.setWindowIcon(QtGui.QIcon("icons/raspinas.png"))
    app.setApplicationName("RaspiNAS-App")
    window = MainWindow()
    sys.exit(app.exec())
