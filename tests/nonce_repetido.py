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

def send_transfer_nonce_repetido(origin, destination, amount):
    # Genera un único nonce
    nonce = hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
    
    # Primera transacción (válida)
    message1 = json.dumps({
        "origin": origin,
        "destination": destination,
        "amount": amount,
        "nonce": nonce
    })
    mac1 = generate_mac(message1)
    request1 = {
        "command": "transfer",
        "origin": origin,
        "destination": destination,
        "amount": amount,
        "nonce": nonce,
        "mac": mac1
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.send(json.dumps(request1).encode())
        response1 = s.recv(1024).decode()
    print("Primera transacción con nonce único:", response1)

    # Segunda transacción (usando el mismo nonce)
    message2 = json.dumps({
        "origin": origin,
        "destination": destination,
        "amount": amount,
        "nonce": nonce
    })
    mac2 = generate_mac(message2)
    request2 = {
        "command": "transfer",
        "origin": origin,
        "destination": destination,
        "amount": amount,
        "nonce": nonce,
        "mac": mac2
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.send(json.dumps(request2).encode())
        response2 = s.recv(1024).decode()
    print("Segunda transacción con nonce repetido:", response2)

send_transfer_nonce_repetido("cuenta1", "cuenta2", "100")
