import socket
import json
import hmac
import hashlib
import time
import random

HOST = '127.0.0.1'
PORT = 3030
SECRET_KEY = b'3f9a6c5e8d4b2a71c0fd34819e7f56a3b2c5d8e9a0f1347d6e8b9c2d1f0a3b4c'

def generate_mac(message):
    return hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()

def test_login_bruteforce(username, wrong_password, attempts=5):
    for i in range(attempts):
        request = {
            "command": "login",
            "username": username,
            "password": wrong_password
        }
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.send(json.dumps(request).encode())
            response = s.recv(1024).decode()
        print(f"Intento {i+1}: {response}")
        time.sleep(1)  # Espera 1 segundo entre intentos para ver el bloqueo

# Asegúrate de tener un usuario válido en la base de datos.
test_login_bruteforce("usuario_test", "contraseña_incorrecta", attempts=5)

