import random
import tkinter as tk
from tkinter import messagebox
import socket
import hashlib
import hmac
import json
import re

# Configuración del cliente
HOST = '127.0.0.1'
PORT = 3030
SECRET_KEY = b'3f9a6c5e8d4b2a71c0fd34819e7f56a3b2c5d8e9a0f1347d6e8b9c2d1f0a3b4c'

# Variable global para indicar si el usuario está logueado
is_logged_in = False
logged_in_username = ""

# Función para enviar datos al servidor
def send_request(command, **args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = json.dumps({"command": command, **args})
        s.send(data.encode())
        response = s.recv(1024).decode()
    return response

# Función para generar MAC
def generate_mac(message):
    return hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()

# Función para validar la política de claves
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
        response = send_request(command="register", username=username, password=password)
        messagebox.showinfo("Respuesta", response)
        if "exitosamente" in response:
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
        response = send_request(command="login", username=username, password=password)
        messagebox.showinfo("Respuesta", response)
        if "exitoso" in response:
            global is_logged_in, logged_in_username
            is_logged_in = True
            logged_in_username = username
            show_transaction_screen(username)
    else:
        messagebox.showwarning("Error", "Usuario y contraseña requeridos.")

# Función para mostrar la pantalla de transacciones
def show_transaction_screen(username):
    clear_screen()
    tk.Label(root, text=f"Bienvenido, {username}").pack()

    tk.Label(root, text="Cuenta Origen:").pack()
    entry_origin = tk.Entry(root)
    entry_origin.pack()

    tk.Label(root, text="Cuenta Destino:").pack()
    entry_destination = tk.Entry(root)
    entry_destination.pack()

    tk.Label(root, text="Monto:").pack()
    entry_amount = tk.Entry(root)
    entry_amount.pack()

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
            messagebox.showinfo("Respuesta", response)
            show_start_screen()
        else:
            messagebox.showwarning("Error", "Todos los campos son obligatorios.")

    tk.Button(root, text="Enviar Transacción", command=send_transaction).pack()
    tk.Button(root, text="Cerrar Sesión", command=logout_user).pack()

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
        tk.Label(root, text="¿Ya eres cliente?").pack()
        tk.Button(root, text="Iniciar Sesión", command=show_login_screen).pack()
        tk.Button(root, text="Registrar", command=show_register_screen).pack()

# Función para mostrar la pantalla de registro
def show_register_screen():
    clear_screen()
    tk.Label(root, text="Registrar Usuario").pack()
    tk.Label(root, text="La contraseña debe tener al menos 8 caracteres, incluyendo letras, números y símbolos.").pack()
    global entry_username, entry_password
    entry_username = tk.Entry(root)
    entry_username.pack()
    entry_password = tk.Entry(root, show="*")
    entry_password.pack()
    tk.Button(root, text="Registrar", command=register_user).pack()
    tk.Button(root, text="Volver", command=show_start_screen).pack()

# Función para mostrar la pantalla de inicio de sesión
def show_login_screen():
    clear_screen()
    tk.Label(root, text="Iniciar Sesión").pack()
    global entry_username, entry_password
    entry_username = tk.Entry(root)
    entry_username.pack()
    entry_password = tk.Entry(root, show="*")
    entry_password.pack()
    tk.Button(root, text="Iniciar Sesión", command=login_user).pack()
    tk.Button(root, text="Volver", command=show_start_screen).pack()

# Función para limpiar la pantalla
def clear_screen():
    for widget in root.winfo_children():
        widget.destroy()

# Interfaz gráfica con Tkinter
root = tk.Tk()
root.title("Cliente Banco - PAI-1")

# Mostrar la pantalla de inicio
show_start_screen()

root.mainloop()
