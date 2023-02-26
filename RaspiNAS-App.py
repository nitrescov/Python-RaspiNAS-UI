# This file represents the frontend to communicate with the socket interface of Python-RaspiNAS.
# Copyright (C) 2023  Nico Pieplow (nitrescov)
# Contact: nitrescov@protonmail.com

# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

import os
import sys
import json
import socket
import struct
import hashlib
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
from tkinter.ttk import Progressbar, Style

VERSION = "1.0.0"  # Initial release (2023/02/18)

# Load the configuration
config_location = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
try:
    with open(config_location, "r") as config_file:
        config = json.load(config_file)
    if not config["language"] or not config["server_ip"] or not config["server_port"]:
        mb.showerror(title="Invalid configuration", message="The configuration file is missing values for 'language', 'server_ip' or 'server_port'.")
        sys.exit(-1)
    LANGUAGE, IP, PORT = config["language"], config["server_ip"], config["server_port"]
except FileNotFoundError:
    mb.showerror(title="Config file not found", message="The configuration file is missing. Please make sure that it is located in the same directory as this tool.")
    sys.exit(-1)
except KeyError:
    mb.showerror(title="Invalid configuration", message="The configuration file does not contain the required keys 'language', 'server_ip' and 'server_port'.")
    sys.exit(-1)

# Constants
BUFFER = 2**27  # Max packet or file buffer size to be cached in RAM (128 MB)
RETRY_COUNT = 5  # Max number of loop passes before an error is raised (must be a positive integer)
SEPARATOR = "\n"

# Communication Protocol:
# SERVER        CLIENT
#       <------- [CMD]
# [RSP] ------->
#       <------- [CDT]      | Optional command data
# [RDT] ------->            | Optional response data
#
# To indicate an invalid checksum, a check response is received after each packet sent:
# SENDING DATA                  RECEIVING DATA              SIZE
# Send header                   Receive header              58 Bytes                    |
# Send data                     Receive data                Length specified in header  |
# Receive check response        Send check response         2 Bytes                     V
#
# Header structure:         [ 8 Bytes packet length | 1 Byte packet command | 1 Byte content type | 48 Bytes SHA384 checksum ]
# Check response structure: [ 1 Byte packet command | 1 Byte validity indicator ]
#
# Packet command structure: [ 1 Bit additional data indicator | 1 Bit response indicator | 6 Bits command type ]

# List of commands and related data (CMDs are expandable up to 0x3f (63), the other command types are calculated depending on them)
CMD_LOGIN = 0x00
CMD_GET_DIRECTORIES = 0x01
CMD_UPLOAD_FILE = 0x02
CMD_DOWNLOAD_FILE = 0x03
CMD_DOWNLOAD_FOLDER = 0x04

CDT_UPLOAD_FILE = CMD_UPLOAD_FILE | (1 << 7)

# List of responses and related data
RSP_LOGIN = CMD_LOGIN | (1 << 6)
RSP_GET_DIRECTORIES = CMD_GET_DIRECTORIES | (1 << 6)
RSP_UPLOAD_FILE = CMD_UPLOAD_FILE | (1 << 6)
RSP_DOWNLOAD_FILE = CMD_DOWNLOAD_FILE | (1 << 6)
RSP_DOWNLOAD_FOLDER = CMD_DOWNLOAD_FOLDER | (1 << 6)

RDT_UPLOAD_FILE = CMD_UPLOAD_FILE | (1 << 6) | (1 << 7)

# List of content types
TYPE_NONE = 0x00
TYPE_DATA = 0x01
TYPE_FILE = 0x02
TYPE_FAILURE = 0x03
TYPE_SUCCESS = 0x04

# List of validity indicator states
CHECK_INVALID = 0x00
CHECK_VALID = 0x01

# Translations
TRANSLATION = {
    "en": {
        "username": "Username",
        "password": "Password",
        "login": "Login",
        "login_error": "Error: Invalid login credentials",
        "no_name_error": "Please fill both login fields.",
        "connection_error": "Error: The connection was refused by the server",
        "timeout_error": "Error: The server is unreachable, check the IP address",
        "upload": "Upload file",
        "download": "Download directory",
        "choose_upload": "Choose a file to upload",
        "choose_download": "Choose a location to save the file",
        "zip_archive": "ZIP Archives",
        "all_files": "All Files",
        "noting_chosen_error": "Error: No file selected",
        "file_not_exists_error": "Error: Selected file doesn\'t exist",
        "choose_dir": "Please select a directory from above.",
        "upload_success": "File uploaded successfully.",
        "download_success": "Directory downloaded successfully.",
        "connection_closed_error": "Error: Connection closed during transfer",
        "file_error": "Error: The requested file doesn\'t exist",
        "file_upload_error": "Error: The uploaded file was refused (invalid path or it already exits)",
        "file_processing_error": "Error: Server cannot process the uploaded file",
        "data_error": "Error: Received invalid data",
        "get_dir_error": "Error: Received invalid response while fetching directories",
        "retry_error": "Error: Communication retry count exceeded",
        "fatal_error": "Fatal error: "
    },
    "de": {
        "username": "Nutzername",
        "password": "Passwort",
        "login": "Anmelden",
        "login_error": "Fehler: Ungültige Anmeldedaten",
        "no_name_error": "Bitte beide Anmeldefelder ausfüllen.",
        "connection_error": "Fehler: Die Verbindung wurde vom Server abgelehnt",
        "timeout_error": "Fehler: Der Server ist nicht erreichbar, überprüfe die IP-Adresse",
        "upload": "Datei hochladen",
        "download": "Verzeichnis herunterladen",
        "choose_upload": "Wähle eine Datei zum Hochladen",
        "choose_download": "Wähle einen Speicherort für die Datei",
        "zip_archive": "ZIP-Archive",
        "all_files": "Alle Dateien",
        "noting_chosen_error": "Fehler: Keine Datei ausgewählt",
        "file_not_exists_error": "Fehler: Die gewählte Datei exisitert nicht",
        "choose_dir": "Bitte ein obenstehendes Verzeichnis auswählen.",
        "upload_success": "Datei erfolgreich hochgeladen.",
        "download_success": "Verzeichnis erfolgreich heruntergeladen.",
        "connection_closed_error": "Fehler: Die Verbindung wurde während der Übertragung getrennt",
        "file_error": "Fehler: Die angeforderte Datei existiert nicht",
        "file_upload_error": "Fehler: Die hochgeladene Datei wurde zurückgewiesen (der Pfad ist falsch oder sie existiert bereits)",
        "file_processing_error": "Fehler: Der Server kann die hochgeladene Datei nicht verarbeiten",
        "data_error": "Fehler: Ungültige Daten empfangen",
        "get_dir_error": "Fehler: Ungültige Antwort beim Abrufen der Verzeichnisse erhalten",
        "retry_error": "Fehler: Anzahl an Kommunikationsversuchen überschritten",
        "fatal_error": "Fataler Fehler: "
    }
}


class ServerError(Exception): pass


class InternalError(Exception): pass


class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()

        def exit_handler():
            try:
                self.connection.close()
                self.login_frame.login_state.set(False)
            except NameError:
                pass
            self.destroy()

        def choose_file():
            self.remove_error()
            self.remove_info()
            self.update_progress(0)
            button_download.config(state="disabled")
            button_upload.config(state="disabled")
            current_path = self.selector_frame.get_path()
            try:
                if current_path == "":
                    raise InternalError("choose_dir")
                source = fd.askopenfilename(filetypes=[(TRANSLATION[LANGUAGE]["zip_archive"], "*.zip"), (TRANSLATION[LANGUAGE]["all_files"], "*")],
                                            initialdir=os.path.expanduser("~"),
                                            parent=self,
                                            title=TRANSLATION[LANGUAGE]["choose_upload"])
                if not source:
                    raise InternalError("noting_chosen_error")
                if not os.path.isfile(source):
                    raise InternalError("file_not_exists_error")
                packet_content = SEPARATOR.join([os.path.basename(source), current_path]).encode("utf-8")
                for counter in range(RETRY_COUNT):  # Send file upload request
                    send_header(self.connection, len(packet_content), CMD_UPLOAD_FILE, TYPE_DATA, calc_hash(packet_content))
                    self.connection.sendall(packet_content)
                    if receive_check_response(self.connection, CMD_UPLOAD_FILE):
                        break
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                for counter in range(RETRY_COUNT):  # Receive file upload response
                    response_len, response_cmd, response_type, response_checksum = receive_header(self.connection)
                    if response_len != 0 or response_cmd != RSP_UPLOAD_FILE:
                        raise ValueError("Invalid response command, next packet size cannot be determined")
                    if response_type == TYPE_FAILURE:
                        send_check_response(self.connection, RSP_UPLOAD_FILE, CHECK_VALID)
                        raise ServerError("file_upload_error")
                    elif response_type == TYPE_SUCCESS:
                        send_check_response(self.connection, RSP_UPLOAD_FILE, CHECK_VALID)
                        break
                    else:
                        raise ValueError("Invalid response data type, next packet type cannot be determined")
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                for counter in range(RETRY_COUNT):  # Server accepts the file, send it
                    file_size = os.path.getsize(source)
                    send_header(self.connection, file_size, CDT_UPLOAD_FILE, TYPE_FILE, calc_hash(source))
                    with open(source, "rb") as send_file:
                        self.place_progress()
                        current_size = 0
                        while True:
                            raw_data = send_file.read(BUFFER)
                            if not raw_data:
                                break
                            self.connection.sendall(raw_data)
                            current_size += len(raw_data)
                            self.update_progress(int((current_size / file_size) * 100))
                    if receive_check_response(self.connection, CDT_UPLOAD_FILE):
                        break
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                for counter in range(RETRY_COUNT):  # Receive file data response
                    response_len, response_cmd, response_type, response_checksum = receive_header(self.connection)
                    if response_len > 0:
                        raise ValueError("Invalid data waiting in receiving pipe")
                    if response_cmd == RDT_UPLOAD_FILE and response_type == TYPE_SUCCESS:
                        send_check_response(self.connection, RDT_UPLOAD_FILE, CHECK_VALID)
                        self.place_info(TRANSLATION[LANGUAGE]["upload_success"])
                        break
                    else:
                        send_check_response(self.connection, RDT_UPLOAD_FILE, CHECK_VALID)
                        raise ServerError("file_processing_error")
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
            except (ServerError, InternalError) as e:
                self.place_error(TRANSLATION[LANGUAGE][str(e)])
            except ConnectionError:
                self.login_frame.place_error(TRANSLATION[LANGUAGE]["connection_closed_error"])
                self.reset_connection()
            except (ValueError, Exception) as e:
                self.login_frame.place_error(TRANSLATION[LANGUAGE]["fatal_error"] + str(e))
                self.reset_connection()
            finally:
                self.remove_progress()
                button_download.config(state="normal")
                button_upload.config(state="normal")

        def choose_dir():
            self.remove_error()
            self.remove_info()
            self.update_progress(0)
            button_download.config(state="disabled")
            button_upload.config(state="disabled")
            current_path = self.selector_frame.get_path()
            try:
                if current_path == "":
                    raise InternalError("choose_dir")
                target = fd.asksaveasfilename(confirmoverwrite=True,
                                              defaultextension=".zip",
                                              filetypes=[(TRANSLATION[LANGUAGE]["zip_archive"], "*.zip")],
                                              initialdir=os.path.expanduser("~"),
                                              parent=self,
                                              title=TRANSLATION[LANGUAGE]["choose_download"])
                if not target:
                    raise InternalError("noting_chosen_error")
                packet_content = current_path.encode("utf-8")
                for counter in range(RETRY_COUNT):  # Send command
                    send_header(self.connection, len(packet_content), CMD_DOWNLOAD_FOLDER, TYPE_DATA, calc_hash(packet_content))
                    self.connection.sendall(packet_content)
                    if receive_check_response(self.connection, CMD_DOWNLOAD_FOLDER):
                        break
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                for counter in range(RETRY_COUNT):  # Receive file
                    packet_len, packet_cmd, packet_type, packet_checksum = receive_header(self.connection)
                    if packet_cmd != RSP_DOWNLOAD_FOLDER:
                        raise ValueError("Invalid response command, next packet size cannot be determined")
                    if packet_type == TYPE_FAILURE and packet_len == 0:
                        send_check_response(self.connection, RSP_DOWNLOAD_FOLDER, CHECK_VALID)
                        raise ServerError("file_error")
                    elif packet_type == TYPE_FILE and packet_len > 0:
                        with open(target, "wb") as new_file:
                            self.place_progress()
                            remaining_len = packet_len
                            while remaining_len > 0:
                                raw_data = self.connection.recv(min(BUFFER, remaining_len))
                                if not raw_data:
                                    raise ConnectionError()
                                new_file.write(raw_data)
                                remaining_len -= len(raw_data)
                                self.update_progress(int((1 - (remaining_len / packet_len)) * 100))
                        if calc_hash(target) == packet_checksum:
                            send_check_response(self.connection, RSP_DOWNLOAD_FOLDER, CHECK_VALID)
                            self.place_info(TRANSLATION[LANGUAGE]["download_success"])
                            break
                        else:
                            send_check_response(self.connection, RSP_DOWNLOAD_FOLDER, CHECK_INVALID)
                            continue
                    else:
                        raise ValueError("Invalid response data type, next packet type cannot be determined")
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
            except (ServerError, InternalError) as e:
                self.place_error(TRANSLATION[LANGUAGE][str(e)])
            except ConnectionError:
                self.login_frame.place_error(TRANSLATION[LANGUAGE]["connection_closed_error"])
                self.reset_connection()
            except (ValueError, Exception) as e:
                self.login_frame.place_error(TRANSLATION[LANGUAGE]["fatal_error"] + str(e))
                self.reset_connection()
            finally:
                self.remove_progress()
                button_download.config(state="normal")
                button_upload.config(state="normal")

        self.protocol("WM_DELETE_WINDOW", exit_handler)
        self.title(f"RaspiNAS-App [{VERSION}]")
        self.geometry("960x600")
        self.resizable(False, False)
        if os.path.isfile("icons/raspinas.gif"):
            self.iconphoto(True, tk.PhotoImage(file="icons/raspinas.gif"))
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.main_frame = tk.Frame(self, background="#59595F")

        self.selector_frame = DirectorySelector(self.main_frame)
        self.label_main_error = tk.Label(self.main_frame, text="", font=("Roboto", 12), anchor="center", bg="#bb0000", fg="#ffffff")
        self.label_main_info = tk.Label(self.main_frame, text=TRANSLATION[LANGUAGE]["choose_dir"], font=("Roboto", 12), anchor="center", bg="#59595F", fg="#ffffff",
                                        highlightthickness=1, highlightbackground="#aaaaaa")
        style = Style()
        style.theme_use("default")
        style.configure("grey.Horizontal.TProgressbar", background="#88DD3A")
        self.progress = Progressbar(self.main_frame, length=470, style="grey.Horizontal.TProgressbar")
        button_upload = tk.Button(self.main_frame, text=TRANSLATION[LANGUAGE]["upload"], font=("Roboto", 12), anchor="center", command=choose_file, bg="#88DD3A", fg="#000000",
                                  activebackground="#66BB18", activeforeground="#000000", borderwidth=0, relief="flat", highlightthickness=0, disabledforeground="#555555")
        button_download = tk.Button(self.main_frame, text=TRANSLATION[LANGUAGE]["download"], font=("Roboto", 12), anchor="center", command=choose_dir, bg="#88DD3A", fg="#000000",
                                  activebackground="#66BB18", activeforeground="#000000", borderwidth=0, relief="flat", highlightthickness=0, disabledforeground="#555555")

        self.selector_frame.place(x=0, y=0, relwidth=1, height=540)
        self.label_main_info.place(x=480, y=550, width=470, height=40)
        button_upload.place(x=10, y=550, width=225, height=40)
        button_download.place(x=245, y=550, width=225, height=40)

        self.login_frame = LoginFrame(self)
        self.login_frame.pack(fill="both", expand=True)

    def place_info(self, info: str):
        self.label_main_info.config(text=info)
        self.label_main_info.place(x=480, y=550, width=470, height=40)
        self.update()

    def remove_info(self):
        self.label_main_info.place_forget()
        self.update()

    def place_error(self, error: str):
        self.label_main_error.config(text=error)
        self.label_main_error.place(x=480, y=550, width=470, height=40)
        self.update()

    def remove_error(self):
        self.label_main_error.place_forget()
        self.update()

    def place_progress(self):
        self.progress.place(x=480, y=550, width=470, height=40)
        self.update()

    def update_progress(self, value: int):
        self.progress.config(value=value)
        self.update()

    def remove_progress(self):
        self.progress.place_forget()
        self.update()

    def reset_connection(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.login_frame.login_state.get():
            self.login_frame.login_state.set(False)

    # Method to replace mainloop() that resets the window if the socket connection is closed
    def handle_socket_connection(self):

        def refresh_directories() -> bool:
            try:
                for counter in range(RETRY_COUNT):
                    send_header(self.connection, 0, CMD_GET_DIRECTORIES, TYPE_NONE, bytes(48))
                    if receive_check_response(self.connection, CMD_GET_DIRECTORIES):
                        break
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                for counter in range(RETRY_COUNT):
                    packet_len, packet_cmd, packet_type, packet_checksum = receive_header(self.connection)
                    if packet_cmd != RSP_GET_DIRECTORIES or packet_type != TYPE_DATA or packet_len < 1:
                        raise ServerError("get_dir_error")
                    packet_content = recvall(self.connection, packet_len)
                    if calc_hash(packet_content) == packet_checksum:
                        send_check_response(self.connection, RSP_GET_DIRECTORIES, CHECK_VALID)
                        break
                    else:
                        send_check_response(self.connection, RSP_GET_DIRECTORIES, CHECK_INVALID)
                        continue
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                folders = packet_content.decode("utf-8").split("\n")
                for f in folders:
                    b = GenericSelectorButton(self.selector_frame.interior, self.selector_frame, f)
                    b.bind("<MouseWheel>", self.selector_frame.scroll_interior)
                    b.bind("<Button-4>", self.selector_frame.scroll_interior)
                    b.bind("<Button-5>", self.selector_frame.scroll_interior)
                    b.pack(fill="x", anchor="nw", pady=1)
                return True
            except (ServerError, InternalError) as e:
                self.login_frame.place_error(TRANSLATION[LANGUAGE][str(e)])
                self.reset_connection()
                return False
            except ConnectionError:
                self.login_frame.place_error(TRANSLATION[LANGUAGE]["connection_closed_error"])
                self.reset_connection()
                return False
            except Exception as e:
                self.login_frame.place_error(TRANSLATION[LANGUAGE]["fatal_error"] + str(e))
                self.reset_connection()
                return False

        try:
            while True:
                self.login_frame.wait_variable(self.login_frame.login_state)
                if self.login_frame.login_state.get():
                    if refresh_directories():
                        self.login_frame.pack_forget()
                        self.main_frame.pack(fill="both", expand=True)
                else:
                    self.main_frame.place_forget()
                    self.login_frame.pack(fill="both", expand=True)
                self.update()
        except tk.TclError:
            return


class LoginFrame(tk.Frame):
    def __init__(self, master: MainWindow):
        super().__init__(master)

        def login(event=None):
            self.remove_error()
            userhash = hashlib.sha384(entry_password.get().encode("utf-8") + entry_username.get().encode("utf-8")).hexdigest()
            entry_password.delete("0", "end")
            username = entry_username.get()
            if not username:
                self.place_error(TRANSLATION[LANGUAGE]["no_name_error"])
                return
            try:
                master.connection.connect((IP, PORT))
                login_packet = SEPARATOR.join([username, userhash]).encode("utf-8")
                for counter in range(RETRY_COUNT):  # Loop for sending the login request
                    send_header(master.connection, len(login_packet), CMD_LOGIN, TYPE_DATA, calc_hash(login_packet))
                    master.connection.sendall(login_packet)
                    if receive_check_response(master.connection, CMD_LOGIN):
                        break
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                for counter in range(RETRY_COUNT):  # Loop for receiving the login response
                    packet_len, packet_cmd, packet_type, packet_checksum = receive_header(master.connection)
                    if packet_cmd != RSP_LOGIN or packet_len != 0:
                        raise ServerError("data_error")
                    else:
                        send_check_response(master.connection, RSP_LOGIN, CHECK_VALID)
                        break
                if counter >= (RETRY_COUNT - 1):
                    raise InternalError("retry_error")
                if packet_type == TYPE_SUCCESS:
                    self.login_state.set(True)
                    return
                elif packet_type == TYPE_FAILURE:
                    raise InternalError("login_error")
                else:
                    raise ServerError("data_error")
            except (ServerError, InternalError) as e:
                self.place_error(TRANSLATION[LANGUAGE][str(e)])
                master.reset_connection()
            except ConnectionRefusedError:
                self.place_error(TRANSLATION[LANGUAGE]["connection_error"])
                master.reset_connection()
            except TimeoutError:
                self.place_error(TRANSLATION[LANGUAGE]["timeout_error"])
                master.reset_connection()
            except ConnectionError:
                self.place_error(TRANSLATION[LANGUAGE]["connection_closed_error"])
                master.reset_connection()
            except Exception as e:
                self.place_error(TRANSLATION[LANGUAGE]["fatal_error"] + str(e))
                master.reset_connection()

        self.login_state = tk.BooleanVar()

        self.config(background="#59595F")
        self.label_login_error = tk.Label(self, text="", font=("Roboto", 12), anchor="center", bg="#bb0000", fg="#ffffff")
        label_header = tk.Label(self, text="RaspiNAS", font=("Roboto", 32, "bold"), anchor="center", bg="#59595F", fg="#88DD3A")
        label_username = tk.Label(self, text=TRANSLATION[LANGUAGE]["username"], font=("Roboto", 10), anchor="center", bg="#59595F", fg="#ffffff")
        label_password = tk.Label(self, text=TRANSLATION[LANGUAGE]["password"], font=("Roboto", 10), anchor="center", bg="#59595F", fg="#ffffff")
        entry_username = tk.Entry(self, font=("Roboto", 12), justify="center", bg="#ffffff", fg="#000000", relief="flat")
        entry_password = tk.Entry(self, font=("Roboto", 12), show="∙", justify="center", bg="#ffffff", fg="#000000", relief="flat")
        button_login = tk.Button(self, text=TRANSLATION[LANGUAGE]["login"], font=("Roboto", 12), anchor="center", command=login, bg="#88DD3A", fg="#000000",
                                 activebackground="#66BB18", activeforeground="#000000", borderwidth=0, relief="flat", highlightthickness=0)

        label_header.place(x=300, y=60, width=360)
        entry_username.place(x=300, y=210, width=360)
        label_username.place(x=300, y=240, width=360)
        entry_password.place(x=300, y=280, width=360)
        label_password.place(x=300, y=310, width=360)
        button_login.place(x=400, y=350, width=160, height=40)

        entry_username.bind("<Return>", login)
        entry_password.bind("<Return>", login)
        button_login.bind("<Return>", login)

    def place_error(self, error: str):
        self.label_login_error.config(text=error)
        self.label_login_error.place(x=10, y=550, width=940, height=40)
        self.update()

    def remove_error(self):
        self.label_login_error.place_forget()
        self.update()


class DirectorySelector(tk.Frame):
    def __init__(self, master: tk.Frame):
        super().__init__(master)

        self.selected_path, self.selected_button = tk.StringVar(), None
        self.selected_path.set("")

        self.config(background="#59595F")
        self.scrollbar = tk.Scrollbar(self, orient="vertical", width=15, bg="#59595F", activebackground="#59595F", relief="flat", borderwidth=1)
        self.scrollbar.pack(fill="y", side="right", expand=False)
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0, yscrollcommand=self.scrollbar.set, background="#59595F")
        self.canvas.pack(fill="both", side="left", expand=True, padx=10, pady=10)
        self.scrollbar.config(command=self.canvas.yview)

        self.interior = tk.Frame(self.canvas, background="#59595F")
        self.canvas.create_window(0, 0, window=self.interior, anchor="nw")

        self.canvas.bind("<MouseWheel>", self.scroll_interior)
        self.canvas.bind("<Button-4>", self.scroll_interior)
        self.canvas.bind("<Button-5>", self.scroll_interior)
        self.interior.bind("<MouseWheel>", self.scroll_interior)
        self.interior.bind("<Button-4>", self.scroll_interior)
        self.interior.bind("<Button-5>", self.scroll_interior)
        self.interior.bind("<Configure>", self.configure_interior)

    def configure_interior(self, event):
        self.canvas.config(scrollregion=(0, 0, self.interior.winfo_reqwidth(), self.interior.winfo_reqheight()))

    def scroll_interior(self, event):
        if event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(5, "units")
        else:
            self.canvas.yview_scroll(-5, "units")

    def set_path(self, path: str, button: tk.Button):
        self.selected_path.set(path)
        self.selected_button = button

    def get_path(self) -> str:
        return self.selected_path.get()

    def get_button(self) -> tk.Button:
        return self.selected_button


class GenericSelectorButton(tk.Button):
    def __init__(self, master: tk.Frame, reference: DirectorySelector, path: str):
        super().__init__(master)

        def update_directory_selector():
            if reference.get_button() is not None:
                reference.get_button().config(bg=self.cget("bg"), fg=self.cget("fg"), activebackground=self.cget("activebackground"))
            self.config(bg="#88DD3A", fg="#000000", activebackground="#88DD3A")
            reference.set_path(path, self)

        path_text = path if len(path) <= 80 else ("..." + path[-77:])
        self.config(text=path_text, font=("Roboto", 10), command=update_directory_selector, anchor="w", bg="#59595F", fg="#ffffff",
                    activebackground="#aaaaaa", activeforeground="#000000", borderwidth=0, relief="flat", highlightthickness=1, highlightbackground="#aaaaaa")


def recvall(sock: socket.socket, data_len: int) -> bytes:
    data = bytearray()
    while len(data) < data_len:
        packet = sock.recv(min(BUFFER, data_len - len(data)))
        if not packet:
            raise ConnectionError("Connection closed during transfer")
        data.extend(packet)
    return bytes(data)


def send_header(sock: socket.socket, msg_len: int, msg_cmd: int, msg_type: int, msg_checksum: bytes) -> None:
    assert len(msg_checksum) == 48  # SHA384 hash length
    sock.sendall(struct.pack("!Q", msg_len) + struct.pack("!B", msg_cmd) + struct.pack("!B", msg_type) + msg_checksum)


def receive_header(sock: socket.socket) -> tuple[int, int, int, bytes]:
    raw_header = recvall(sock, 58)
    return struct.unpack("!Q", raw_header[:8])[0], raw_header[8], raw_header[9], raw_header[10:]


def send_check_response(sock: socket.socket, msg_cmd: int, validity_indicator: int) -> None:
    sock.sendall(struct.pack("!B", msg_cmd) + struct.pack("!B", validity_indicator))


def receive_check_response(sock: socket.socket, msg_cmd: int) -> bool:
    raw_response = recvall(sock, 2)
    if raw_response[0] != msg_cmd:
        raise ValueError("Received check response does not match the associated command type")
    return True if raw_response[1] == CHECK_VALID else False


def calc_hash(obj) -> bytes:
    hash_object = hashlib.sha384()
    if isinstance(obj, bytes):
        hash_object.update(obj)
        return hash_object.digest()
    elif isinstance(obj, str):
        if not os.path.isfile(obj):
            raise ValueError("The file to be hashed does not exist")
        with open(obj, "rb") as f:
            while True:
                data = f.read(BUFFER)
                if not data:
                    break
                hash_object.update(data)
        return hash_object.digest()
    else:
        raise Exception("The object to be hashed must be of type bytes or a path string")


if __name__ == "__main__":
    MainWindow().handle_socket_connection()
