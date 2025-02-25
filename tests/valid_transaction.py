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

def send_transfer(origin, destination, amount):
    nonce = hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
    message = json.dumps({
        "origin": origin,
        "destination": destination,
        "amount": amount,
        "nonce": nonce
    })
    mac = generate_mac(message)
    request = {
        "command": "transfer",
        "origin": origin,
        "destination": destination,
        "amount": amount,
        "nonce": nonce,
        "mac": mac
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.send(json.dumps(request).encode())
        response = s.recv(1024).decode()
    print("Respuesta transacción válida:", response)

send_transfer("cuenta1", "cuenta2", "100")
