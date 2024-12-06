from scapy.all import *
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_parameters, load_pem_public_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import socket
import random
import time
import ctypes

# Hàm ghi đè bộ nhớ
def secure_zeroize(data):
    if isinstance(data, (bytes, bytearray)):
        buffer = ctypes.create_string_buffer(len(data))
        ctypes.memset(ctypes.addressof(buffer), 0, len(data))
        del buffer

# Địa chỉ IP và cổng của receiver
destination_ip = "10.11.12.10"
port = 80

try:
    print(f"Connecting to Receiver at {destination_ip}:{port}...")
    with socket.create_connection((destination_ip, port), timeout=10) as conn:
        print("Connected to Receiver.")

        # Nhận tham số Diffie-Hellman từ Receiver
        parameters_bytes = conn.recv(4096)
        if not parameters_bytes:
            raise ValueError("No Diffie-Hellman parameters received from Receiver.")
        parameters = load_pem_parameters(parameters_bytes)
        print("Received Diffie-Hellman parameters from Receiver.")

        # Tạo khóa riêng và khóa công khai
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        # Gửi public key tới Receiver
        conn.sendall(public_key_bytes)
        print("Sent public key to Receiver.")

        # Nhận public key từ Receiver
        receiver_public_key_bytes = conn.recv(4096)
        if not receiver_public_key_bytes:
            raise ValueError("No public key received from Receiver.")
        receiver_public_key = load_pem_public_key(receiver_public_key_bytes)
        print("Successfully loaded Receiver's public key.")

        # Tạo shared key
        shared_key = private_key.exchange(receiver_public_key)

        # Dẫn xuất khóa AES từ shared key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"dh key exchange"
        ).derive(shared_key)
        print(f"Derived AES key: {derived_key.hex()}")

        # Mã hóa thông điệp bằng AES
        def encrypt_aes(key, plaintext):
            cipher = AES.new(key, AES.MODE_ECB)
            padded_text = pad(plaintext.encode(), AES.block_size)  # Căn chỉnh dữ liệu
            ciphertext = cipher.encrypt(padded_text)
            return base64.b64encode(ciphertext)

        # Thông điệp cần mã hóa
        hidden_message = "HELLO, HOW ARE YOU?"
        try:
            encrypted_message = encrypt_aes(derived_key, hidden_message)
            print(f"Encrypted message: {encrypted_message}")
        except Exception as e:
            print(f"Failed to encrypt message: {e}")
            exit()

        # Chia nhỏ thông điệp mã hóa thành các mảnh (chunks)
        message_chunks = [encrypted_message[i:i + 4] for i in range(0, len(encrypted_message), 4)]

        for i, chunk in enumerate(message_chunks):
            try:
                # Chuyển chunk thành số nguyên
                encoded_chunk = int.from_bytes(chunk.ljust(4, b'\x00'), 'big') % (2**32)

                # Nhúng chunk vào trường Timestamp
                encrypted_packet = IP(dst=destination_ip) / TCP(sport=12345, dport=80, flags="P", options=[("Timestamp", (encoded_chunk, 0))])
                time.sleep(0.5)  
                send(encrypted_packet, verbose=0)
                print(f"Sent encrypted message chunk {i + 1}/{len(message_chunks)}.")
            except Exception as e:
                print(f"Failed to send message chunk {i + 1}: {e}")

        # Gửi gói tin kết thúc
        try:
            termination_packet = IP(dst=destination_ip) / TCP(sport=12345, dport=80, flags="P", options=[("Timestamp", (0xFFFFFFFF, 0))])
            send(termination_packet, verbose=0)
            print("Sent termination packet to signal end of transmission.")
        except Exception as e:
            print(f"Failed to send termination packet: {e}")

        # Xóa shared key và derived key khỏi bộ nhớ
        secure_zeroize(shared_key)
        secure_zeroize(derived_key)
        del private_key, public_key
        print("Sensitive keys cleared from memory.")

except Exception as e:
    print(f"Failed to connect to Receiver or send data: {e}")