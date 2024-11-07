import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import base64
import os
import sys

current_version = "1.2.4"

def load_configuration():
    default_config = {
        "directory": "C:/Example Files",
        "port": 8000,
        "ip": "localhost",
        "auth_required": False,
        "username": "danbenba",
        "password": "password"
    }
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        with open('config.json', 'w') as config_file:
            json.dump(default_config, config_file, indent=4)
        config = default_config
    return config

class AuthHandler(SimpleHTTPRequestHandler):
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Test"')
        self.end_headers()

    def do_GET(self):
        if self.server.auth_required:
            if self.headers.get('Authorization') == self.server.auth_token:
                return SimpleHTTPRequestHandler.do_GET(self)
            else:
                self.do_AUTHHEAD()
                self.wfile.write(b"Authentication required.")
        else:
            return SimpleHTTPRequestHandler.do_GET(self)

    def translate_path(self, path):
        path = super().translate_path(path)
        rel_path = os.path.relpath(path, os.getcwd())
        return os.path.join(self.server.directory, rel_path)

class ThreadedHTTPServer(HTTPServer):
    def serve_forever(self, poll_interval=0.5):
        self._thread = threading.Thread(target=super().serve_forever, args=(poll_interval,), daemon=True)
        self._thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()
        self._thread.join()

class TextRedirector(object):
    def __init__(self, widget):
        self.widget = widget

    def write(self, string):
        self.widget.config(state='normal')
        self.widget.insert('end', string)
        self.widget.see('end')
        self.widget.config(state='disabled')

    def flush(self):
        pass

class ServerApp(tk.Tk):
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.title("LHServer")
        self.geometry("956x626")
        self.server = None
        self.auth_required_var = tk.BooleanVar(value=self.config.get("auth_required", False))
        self.show_password_var = tk.BooleanVar(value=False)  # Variable pour suivre l'état d'affichage du mot de passe
        self.create_widgets()


    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        directory_frame = ttk.Frame(main_frame)
        directory_frame.pack(fill=tk.X, pady=5)
        ttk.Label(directory_frame, text="Directory to share:").pack(side=tk.LEFT)
        self.directory_entry = ttk.Entry(directory_frame, width=50)
        self.directory_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.directory_entry.insert(0, self.config.get('directory', 'C:/Example Files'))
        ttk.Button(directory_frame, text="Choose", command=self.choose_directory).pack(side=tk.LEFT)

        port_frame = ttk.Frame(main_frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(port_frame)
        self.port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.port_entry.insert(0, str(self.config.get('port', 8000)))

        ip_frame = ttk.Frame(main_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ip_frame, text="IP Address:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ip_entry.insert(0, self.config.get('ip', 'localhost'))

        # Authentification
        auth_frame = ttk.Frame(main_frame)
        auth_frame.pack(fill=tk.X, pady=5)
        ttk.Label(auth_frame, text="Enable Authentication:").pack(side=tk.LEFT)
        auth_check = ttk.Checkbutton(auth_frame, variable=self.auth_required_var, onvalue=True, offvalue=False, command=self.toggle_auth_fields)
        auth_check.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Configuration des champs d'authentification
        self.configure_auth_fields(main_frame)

        # Initialisation des champs de nom d'utilisateur et de mot de passe sans les afficher
        self.username_frame = ttk.Frame(main_frame)
        ttk.Label(self.username_frame, text="Username:").pack(side=tk.LEFT)
        self.username_entry = ttk.Entry(self.username_frame)
        self.username_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.username_entry.insert(0, self.config.get('username', 'user'))

        self.password_frame = ttk.Frame(main_frame)
        ttk.Label(self.password_frame, text="Custom Password:").pack(side=tk.LEFT)
        self.password_entry = ttk.Entry(self.password_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.password_entry.insert(0, self.config.get('password', 'password'))

        # Affichage conditionnel basé sur l'état de la case à cocher
        self.toggle_auth_fields()

        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        ttk.Button(buttons_frame, text="Start Server", command=self.start_server).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(buttons_frame, text="Stop Server", command=self.stop_server).pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.status_label = ttk.Label(main_frame, text="Server not running")
        self.status_label.pack(fill=tk.X, pady=5)

        self.logs_text = scrolledtext.ScrolledText(main_frame, state='disabled', height=10)
        self.logs_text.pack(fill=tk.BOTH, expand=True, pady=5)

        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(footer_frame, text="Powered by danbenba", foreground="gray").pack(side=tk.BOTTOM, anchor='center')
        ttk.Label(footer_frame, text=current_version, foreground="gray").pack(side=tk.BOTTOM, anchor='center')

    def configure_auth_fields(self, main_frame):
        # Configuration du champ Username
        self.username_frame = ttk.Frame(main_frame)
        ttk.Label(self.username_frame, text="Username:").pack(side=tk.LEFT)
        self.username_entry = ttk.Entry(self.username_frame)
        self.username_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.username_entry.insert(0, self.config.get('username', 'user'))

        # Configuration du champ Password
        self.password_frame = ttk.Frame(main_frame)
        ttk.Label(self.password_frame, text="Custom Password:").pack(side=tk.LEFT)
        self.password_entry = ttk.Entry(self.password_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.password_entry.insert(0, self.config.get('password', 'password'))
        
        show_password_button = ttk.Button(self.password_frame, text="Show Password", command=self.toggle_password_show)
        show_password_button.pack(side=tk.LEFT)
        
        display_password_button = ttk.Button(self.password_frame, text="Display Password", command=self.display_current_password)
        display_password_button.pack(side=tk.LEFT)

        # Assurez-vous que cet appel est déplacé ici, après que tous les widgets ont été créés
        self.toggle_auth_fields()



    def toggle_auth_fields(self):
        if self.auth_required_var.get():
            self.username_frame.pack(fill=tk.X, pady=5)
            self.password_frame.pack(fill=tk.X, pady=5)
        else:
            self.username_frame.pack_forget()
            self.password_frame.pack_forget()

    def toggle_password_show(self):
        self.show_password_var.set(not self.show_password_var.get())
        self.password_entry.config(show="" if self.show_password_var.get() else "*")
        # Mettre à jour le texte du bouton en fonction de l'état
        for widget in self.password_frame.winfo_children():
            if isinstance(widget, ttk.Button):
                widget.config(text="Hide Password" if self.show_password_var.get() else "Show Password")

    def display_current_password(self):
        # Affiche le mot de passe actuel dans une boîte de dialogue
        current_password = self.password_entry.get()
        messagebox.showinfo("Current Password", f"The current password is: {current_password}")


    def choose_directory(self):
        folder_selected = filedialog.askdirectory()
        self.directory_entry.delete(0, tk.END)
        self.directory_entry.insert(0, folder_selected)

    def start_server(self):
        directory = self.directory_entry.get()
        port = int(self.port_entry.get())
        host = self.ip_entry.get()
        auth_required = self.auth_required_var.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_pass = f"{username}:{password}"
        auth_token = base64.b64encode(user_pass.encode('utf-8')).decode('utf-8')

        sys.stdout = TextRedirector(self.logs_text)
        sys.stderr = TextRedirector(self.logs_text)

        try:
            handler = AuthHandler
            self.server = ThreadedHTTPServer((host, port), handler)
            self.server.directory = directory
            self.server.auth_required = auth_required
            if auth_required:
                self.server.auth_token = "Basic " + auth_token
            self.status_label.config(text=f"Server running on {host}:{port} with authentication {'enabled' if auth_required else 'disabled'}")
            self.server.serve_forever()
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start the server: {e}")

    def stop_server(self):
        if self.server:
            self.server.stop()
            self.status_label.config(text="Server stopped")
            self.server = None
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

if __name__ == "__main__":
    config = load_configuration()
    app = ServerApp(config)
    app.mainloop()
