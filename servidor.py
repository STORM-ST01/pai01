# Proyecto PAI-1 Integridos
# Cliente-Servidor con Sockets y Tkinter

import socket
import threading
import sqlite3
import bcrypt
import hmac
import hashlib
import os
import json
from datetime import datetime

# Configuración del servidor
HOST = '127.0.0.1'
PORT = 3030
SECRET_KEY = b'3f9a6c5e8d4b2a71c0fd34819e7f56a3b2c5d8e9a0f1347d6e8b9c2d1f0a3b4c'

# Base de datos SQLite
conn = sqlite3.connect("pai1.db", check_same_thread=False)
cursor = conn.cursor()

# Crear tablas si no existen
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT NOT NULL
)
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT UNIQUE
)
""")
conn.commit()


# Función para hashear contraseñas
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

# Función para verificar contraseña
def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# Función para generar MAC
def generate_mac(message):
    return hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()

# Manejador de cliente
def handle_client(client_socket):
    try:
        data = client_socket.recv(1024).decode()
        if not data:
            return

        try:
            request = json.loads(data)
        except json.JSONDecodeError:
            client_socket.send("Error: Formato JSON inválido.".encode('utf-8'))
            return

        command = request.get("command")

        if command == "register":
            username = request.get("username")
            password = request.get("password")
            if username and password:
                hashed_password = hash_password(password)
                try:
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                    conn.commit()
                    client_socket.send(b"Usuario registrado exitosamente.")
                except sqlite3.IntegrityError:
                    client_socket.send(b"Error: Usuario ya registrado.")
            else:
                client_socket.send(b"Error: Datos incompletos para el registro.")

        elif command == "login":
            username = request.get("username")
            password = request.get("password")
            if username and password:
                cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                if user and verify_password(password, user[0]):
                    client_socket.send("Inicio de sesión exitoso.".encode('utf-8'))
                else:
                    client_socket.send("Error: Inicio de sesión fallido.".encode('utf-8'))
            else:
                client_socket.send(b"Error: Datos incompletos para el login.")

        elif command == "transfer":
            origin = request.get("origin")
            destination = request.get("destination")
            amount = request.get("amount")
            nonce = request.get("nonce")
            mac = request.get("mac")

            if not origin or not destination or not amount or not nonce or not mac:
                client_socket.send(b"Error: Datos incompletos para la transferencia.")
                return

            if int(amount) < 0:
                client_socket.send(b"Error: Monto negativo no permitido.")
                return

            if origin and destination and amount and nonce:
                
                # Verificar si el nonce ya existe para evitar ataques de repetición
                cursor.execute("SELECT * FROM nonces WHERE nonce = ?", (nonce,))
                if cursor.fetchone() == nonce:
                    client_socket.send(b"Error: Nonce repetido. Transaccion rechazada.")
                    return
                cursor.execute("INSERT INTO nonces (nonce) VALUES (?)", (nonce,))
                conn.commit()
                message = json.dumps({
                    "origin": origin,
                    "destination": destination,
                    "amount": amount,
                    "nonce": nonce
                })
                mac_gen = generate_mac(message)
                if mac_gen != mac:
                    client_socket.send("Error: MAC inválido.")
                    return

                client_socket.send(b"Transferencia realizada con integridad.")
            else:
                client_socket.send("Error: Datos incompletos para la transacción.".encode('utf-8'))

        else:
            client_socket.send(f"Error: Comando no reconocido.{command}".encode('utf-8'))

    except Exception as e:
        print(f"Error: {e}")
        client_socket.send(b"Error en el servidor.")
    finally:
        client_socket.close()

# Servidor
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"[SERVIDOR] Escuchando en {HOST}:{PORT}")

# Hilo para cada conexión entrante
while True:
    client_socket, addr = server.accept()
    print(f"[NUEVA CONEXIÓN] Cliente conectado desde {addr}")
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()