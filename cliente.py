import random
import tkinter as tk
from tkinter import messagebox
import socket
import hashlib
import hmac
import json
import re

# IMPORTANTE: necesitamos Pillow para cargar PNG/JPG
from PIL import Image, ImageTk

# Configuración del cliente
HOST = '127.0.0.1'
PORT = 3030
SECRET_KEY = b'3f9a6c5e8d4b2a71c0fd34819e7f56a3b2c5d8e9a0f1347d6e8b9c2d1f0a3b4c'

# Variables globales para el estado de sesión
is_logged_in = False
logged_in_username = ""

# Función para enviar datos al servidor y recibir respuesta en JSON
def send_request(command, **args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = json.dumps({"command": command, **args})
        s.send(data.encode())
        response = s.recv(1024).decode()
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        return {"success": False, "message": "Respuesta con formato inválido."}

# Función para generar MAC
def generate_mac(message):
    return hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()

# Función para validar la política de contraseñas
def validate_password_policy(password):
    if len(password) <= 8:
        return False
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@\$%\&\*\_\-=\{\}\[\]:;<>?,./\\]', password):
        return False
    return True

# Función de registro
def register_user():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        if not validate_password_policy(password):
            messagebox.showwarning("Error", "La contraseña debe tener al menos 8 caracteres, incluyendo letras, números y símbolos.")
            return
        response = send_request("register", username=username, password=password)
        messagebox.showinfo("Respuesta", response.get("message", ""))
        if response.get("success"):
            global is_logged_in, logged_in_username
            is_logged_in = True
            logged_in_username = username
            show_transaction_screen(username)
    else:
        messagebox.showwarning("Error", "Usuario y contraseña requeridos.")

# Función de inicio de sesión
def login_user():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        response = send_request("login", username=username, password=password)
        messagebox.showinfo("Respuesta", response.get("message", ""))
        if response.get("success"):
            global is_logged_in, logged_in_username
            is_logged_in = True
            logged_in_username = username
            show_transaction_screen(username)
    else:
        messagebox.showwarning("Error", "Usuario y contraseña requeridos.")

# Función para mostrar la pantalla de transacciones
def show_transaction_screen(username):
    clear_screen()
    title = tk.Label(main_frame, text=f"Bienvenido, {username}", font=("Helvetica", 16, "bold"), bg="#f0f0f0")
    title.pack(pady=10)
    
    form_frame = tk.Frame(main_frame, bg="#f0f0f0")
    form_frame.pack(pady=20)
    
    tk.Label(form_frame, text="Cuenta Origen:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    entry_origin = tk.Entry(form_frame, font=("Helvetica", 12))
    entry_origin.grid(row=0, column=1, padx=5, pady=5)
    
    tk.Label(form_frame, text="Cuenta Destino:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    entry_destination = tk.Entry(form_frame, font=("Helvetica", 12))
    entry_destination.grid(row=1, column=1, padx=5, pady=5)
    
    tk.Label(form_frame, text="Monto:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=2, column=0, padx=5, pady=5, sticky="e")
    entry_amount = tk.Entry(form_frame, font=("Helvetica", 12))
    entry_amount.grid(row=2, column=1, padx=5, pady=5)
    
    def send_transaction():
        origin = entry_origin.get()
        destination = entry_destination.get()
        amount = entry_amount.get()
        if origin and destination and amount:
            nonce = hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
            message = json.dumps({
                "origin": origin,
                "destination": destination,
                "amount": amount,
                "nonce": nonce
            })
            mac = generate_mac(message)
            response = send_request("transfer", origin=origin, destination=destination, amount=amount, nonce=nonce, mac=mac)
            messagebox.showinfo("Respuesta", response.get("message", ""))
            show_start_screen()
        else:
            messagebox.showwarning("Error", "Todos los campos son obligatorios.")
    
    btn_frame = tk.Frame(main_frame, bg="#f0f0f0")
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="Enviar Transacción", font=("Helvetica", 12), command=send_transaction, width=20).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(btn_frame, text="Cerrar Sesión", font=("Helvetica", 12), command=logout_user, width=20).grid(row=0, column=1, padx=5, pady=5)

# Función para cerrar sesión
def logout_user():
    global is_logged_in, logged_in_username
    is_logged_in = False
    logged_in_username = ""
    show_start_screen()

# Función para mostrar la pantalla de inicio
def show_start_screen():
    clear_screen()
    if is_logged_in:
        show_transaction_screen(logged_in_username)
    else:
        title = tk.Label(main_frame, text="Cliente Banco - PAI-1", font=("Helvetica", 18, "bold"), bg="#f0f0f0")
        title.pack(pady=10)
        
        btn_frame = tk.Frame(main_frame, bg="#f0f0f0")
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Iniciar Sesión", font=("Helvetica", 12), command=show_login_screen, width=20).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(btn_frame, text="Registrar", font=("Helvetica", 12), command=show_register_screen, width=20).grid(row=0, column=1, padx=10, pady=10)

# Función para mostrar la pantalla de registro
def show_register_screen():
    clear_screen()
    title = tk.Label(main_frame, text="Registrar Usuario", font=("Helvetica", 18, "bold"), bg="#f0f0f0")
    title.pack(pady=20)
    
    info = tk.Label(main_frame, text="La contraseña debe tener al menos 8 caracteres, incluyendo letras, números y símbolos.\nSímbolos permitidos: !@\$%\&\*\_\-=\{\}\[\]:;<>?,./\\", 
                    font=("Helvetica", 10), bg="#f0f0f0")
    info.pack(pady=5)
    
    form_frame = tk.Frame(main_frame, bg="#f0f0f0")
    form_frame.pack(pady=10)
    tk.Label(form_frame, text="Usuario:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    global entry_username
    entry_username = tk.Entry(form_frame, font=("Helvetica", 12))
    entry_username.grid(row=0, column=1, padx=5, pady=5)
    
    tk.Label(form_frame, text="Contraseña:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    global entry_password
    entry_password = tk.Entry(form_frame, show="*", font=("Helvetica", 12))
    entry_password.grid(row=1, column=1, padx=5, pady=5)
    
    btn_frame = tk.Frame(main_frame, bg="#f0f0f0")
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="Registrar", font=("Helvetica", 12), command=register_user, width=20).grid(row=0, column=0, padx=10, pady=10)
    tk.Button(btn_frame, text="Volver", font=("Helvetica", 12), command=show_start_screen, width=20).grid(row=0, column=1, padx=10, pady=10)

# Función para mostrar la pantalla de inicio de sesión
def show_login_screen():
    clear_screen()
    title = tk.Label(main_frame, text="Iniciar Sesión", font=("Helvetica", 18, "bold"), bg="#f0f0f0")
    title.pack(pady=20)
    
    form_frame = tk.Frame(main_frame, bg="#f0f0f0")
    form_frame.pack(pady=10)
    tk.Label(form_frame, text="Usuario:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    global entry_username
    entry_username = tk.Entry(form_frame, font=("Helvetica", 12))
    entry_username.grid(row=0, column=1, padx=5, pady=5)
    
    tk.Label(form_frame, text="Contraseña:", font=("Helvetica", 12), bg="#f0f0f0").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    global entry_password
    entry_password = tk.Entry(form_frame, show="*", font=("Helvetica", 12))
    entry_password.grid(row=1, column=1, padx=5, pady=5)
    
    btn_frame = tk.Frame(main_frame, bg="#f0f0f0")
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="Iniciar Sesión", font=("Helvetica", 12), command=login_user, width=20).grid(row=0, column=0, padx=10, pady=10)
    tk.Button(btn_frame, text="Volver", font=("Helvetica", 12), command=show_start_screen, width=20).grid(row=0, column=1, padx=10, pady=10)

# Función para limpiar la pantalla
def clear_screen():
    for widget in main_frame.winfo_children():
        widget.destroy()

# Configuración de la ventana principal
root = tk.Tk()
root.title("Cliente Banco - PAI-1")
root.geometry("500x400")
root.configure(bg="#f0f0f0")

# Marco principal para el contenido
main_frame = tk.Frame(root, bg="#f0f0f0")
main_frame.pack(fill="both", expand=True)

# Footer fijo en la parte inferior de la ventana
footer_frame = tk.Frame(root, bg="#f0f0f0")
footer_frame.pack(side="bottom", fill="x")

# Cargar y redimensionar el logo
try:
    logo_path = "insegus_logo.png"  
    img = Image.open(logo_path)
  
    img = img.resize((90, 60), Image.Resampling.LANCZOS)
    logo_img = ImageTk.PhotoImage(img)

    logo_label = tk.Label(footer_frame, image=logo_img, bg="#f0f0f0")
    logo_label.image = logo_img  
    logo_label.pack(side="left", padx=5)
except Exception as e:
    print("Error cargando el logo:", e)

footer_label = tk.Label(footer_frame, text="Designed and Protected by Security Team 01 - INSEGUS", font=("Helvetica", 10), bg="#f0f0f0")
footer_label.pack(pady=5)

show_start_screen()
root.mainloop()
