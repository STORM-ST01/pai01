import socket
import threading
import sqlite3
import bcrypt
import hmac
import hashlib
import os
import json
import time
import logging
from datetime import datetime

# Configuración del logging: Se registran en 'server.log'
logging.basicConfig(
    filename='server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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

# Variables globales para protección contra brute force en login
login_attempts = {}
LOGIN_THRESHOLD = 3   # Número máximo de intentos permitidos
BLOCK_TIME = 60       # Tiempo de bloqueo en segundos
login_attempts_lock = threading.Lock()

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

# Función para enviar respuestas en JSON
def send_json(client_socket, success, message):
    response = json.dumps({"success": success, "message": message})
    client_socket.send(response.encode('utf-8'))

# Manejador de cliente
def handle_client(client_socket):
    try:
        data = client_socket.recv(1024).decode()
        if not data:
            logging.warning("Se recibió un paquete vacio.")
            return

        try:
            request = json.loads(data)
        except json.JSONDecodeError:
            send_json(client_socket, False, "Error: Formato JSON inválido.")
            logging.error("JSON invalido recibido.")
            return

        command = request.get("command")
        logging.info(f"Comando recibido: {command}")

        if command == "register":
            username = request.get("username")
            password = request.get("password")
            logging.info(f"Registro solicitado para usuario: {username}")
            if username and password:
                hashed_password = hash_password(password)
                try:
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                    conn.commit()
                    send_json(client_socket, True, "Usuario registrado exitosamente.")
                    logging.info(f"Usuario {username} registrado exitosamente.")
                except sqlite3.IntegrityError:
                    send_json(client_socket, False, "Error: Usuario ya registrado.")
                    logging.warning(f"Registro fallido: usuario {username} ya existe.")
            else:
                send_json(client_socket, False, "Error: Datos incompletos para el registro.")
                logging.error("Registro fallido: datos incompletos.")

        elif command == "login":
            username = request.get("username")
            password = request.get("password")
            logging.info(f"Login solicitado para usuario: {username}")
            if username and password:
                current_time = datetime.now().timestamp()
                with login_attempts_lock:
                    if username in login_attempts:
                        attempts, blocked_until = login_attempts[username]
                        if blocked_until is not None and current_time < blocked_until:
                            send_json(client_socket, False, "Error: Cuenta bloqueada temporalmente. Intente más tarde.")
                            logging.warning(f"Usuario {username} bloqueado hasta {datetime.fromtimestamp(blocked_until)}.")
                            return

                cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                if user and verify_password(password, user[0]):
                    with login_attempts_lock:
                        if username in login_attempts:
                            del login_attempts[username]
                    send_json(client_socket, True, "Inicio de sesión exitoso.")
                    logging.info(f"Usuario {username} inicio sesion correctamente.")
                else:
                    with login_attempts_lock:
                        if username in login_attempts:
                            attempts, blocked_until = login_attempts[username]
                            attempts += 1
                            if attempts >= LOGIN_THRESHOLD:
                                blocked_until = current_time + BLOCK_TIME
                                logging.warning(f"Usuario {username} bloqueado tras {attempts} intentos fallidos.")
                            login_attempts[username] = (attempts, blocked_until)
                        else:
                            login_attempts[username] = (1, None)
                    send_json(client_socket, False, "Error: Inicio de sesión fallido.")
                    logging.warning(f"Inicio de sesion fallido para {username}.")
            else:
                send_json(client_socket, False, "Error: Datos incompletos para el login.")
                logging.error("Login fallido: datos incompletos.")

        elif command == "transfer":
            origin = request.get("origin")
            destination = request.get("destination")
            amount = request.get("amount")
            nonce = request.get("nonce")
            mac = request.get("mac")
            logging.info(f"Transferencia solicitada: {origin} -> {destination}, monto: {amount}")

            if not origin or not destination or not amount or not nonce or not mac:
                send_json(client_socket, False, "Error: Datos incompletos para la transferencia.")
                logging.error("Transferencia fallida: datos incompletos.")
                return

            if int(amount) < 0:
                send_json(client_socket, False, "Error: Monto negativo no permitido.")
                logging.error("Transferencia fallida: monto negativo.")
                return

            # Verificar si el nonce ya existe para evitar ataques de repetición
            cursor.execute("SELECT * FROM nonces WHERE nonce = ?", (nonce,))
            if cursor.fetchone() is not None:
                send_json(client_socket, False, "Error: Nonce repetido. Transacción rechazada.")
                logging.warning(f"Transferencia rechazada: nonce repetido {nonce}.")
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
            start_time = time.perf_counter()
            if not hmac.compare_digest(mac_gen, mac):
                elapsed = time.perf_counter() - start_time
                send_json(client_socket, False, "Error: MAC inválido.")
                logging.warning(f"MAC invalido. Tiempo comparación: {elapsed:.6f}s. MAC esperado: {mac_gen}, recibido: {mac}")
                return
            else:
                elapsed = time.perf_counter() - start_time
                logging.info(f"MAC verificado correctamente. Tiempo comparacion: {elapsed:.6f}s.")

            send_json(client_socket, True, "Transferencia realizada con integridad.")
            logging.info(f"Transferencia de {amount} de {origin} a {destination} completada.")

        else:
            send_json(client_socket, False, f"Error: Comando no reconocido: {command}")
            logging.error(f"Comando no reconocido: {command}")

    except Exception as e:
        logging.error(f"Error en handle_client: {e}")
        send_json(client_socket, False, "Error en el servidor.")
    finally:
        client_socket.close()

# Servidor: escucha conexiones entrantes y lanza un hilo por cada cliente
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
logging.info(f"[SERVIDOR] Escuchando en {HOST}:{PORT}")
print(f"[SERVIDOR] Escuchando en {HOST}:{PORT}")

while True:
    client_socket, addr = server.accept()
    logging.info(f"[NUEVA CONEXION] Cliente conectado desde {addr}")
    print(f"[NUEVA CONEXIÓN] Cliente conectado desde {addr}")
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
