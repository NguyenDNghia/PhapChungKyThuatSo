import pyshark
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key, ParameterFormat
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import socket
import ctypes

# Cấu hình giao diện và bộ lọc
interface_name = "VMware Network Adapter VMnet8"
display_filter = "tcp and ip.dst == 10.11.12.10 and tcp.port == 80"
termination_tsval = 0xFFFFFFFF  # Giá trị báo hiệu kết thúc

# 1. Tạo Diffie-Hellman parameters cho receiver
parameters = dh.generate_parameters(generator=2, key_size=2048)
parameters_bytes = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

# Tạo khóa riêng và công khai
private_key = parameters.generate_private_key()
public_key = private_key.public_key()
public_key_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

# 2. Thiết lập TCP server để nhận kết nối
receiver_ip = "0.0.0.0"
port = 80

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((receiver_ip, port))
        s.listen()
        print(f"Listening on port {port}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # Gửi tham số Diffie-Hellman tới sender
            conn.sendall(parameters_bytes)
            print("Sent Diffie-Hellman parameters to Sender.")

            # Nhận public key từ sender
            sender_public_key_bytes = conn.recv(4096)
            if not sender_public_key_bytes:
                raise ValueError("No public key received from Sender.")
            sender_public_key = load_pem_public_key(sender_public_key_bytes)
            print("Successfully loaded Sender's public key.")

            # Gửi public key của receiver
            conn.sendall(public_key_bytes)
            print("Sent public key to Sender.")

            # Tạo shared key
            shared_key = private_key.exchange(sender_public_key)

            # Dẫn xuất khóa AES từ shared key
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=None,
                info=b"dh key exchange"
            ).derive(shared_key)
            print(f"Derived AES key: {derived_key.hex()}")

except Exception as e:
    print(f"Error: {e}")

# 3. Nhận dữ liệu mã hóa qua TCP Timestamp
print(f"Bắt gói tin với bộ lọc: {display_filter}...")

encrypted_message_chunks = []

try:
    capture = pyshark.LiveCapture(interface=interface_name, display_filter=display_filter)

    for packet in capture.sniff_continuously():
        try:
            if 'IP' in packet and 'TCP' in packet:
                if hasattr(packet.tcp, 'flags') and int(packet.tcp.flags, 16) & 0x08:  # Chỉ xử lý gói PSH
                    print(f"IP nguồn: {packet.ip.src}, IP đích: {packet.ip.dst}")
                    print(f"Cổng nguồn: {packet.tcp.srcport}, Cổng đích: {packet.tcp.dstport}")

                    if hasattr(packet.tcp, 'options') and packet.tcp.options:
                        print(f"TCP Options (raw): {packet.tcp.options}")

                        # Chuyển đổi TCP options từ hex sang byte array
                        options_bytes = bytes.fromhex(packet.tcp.options.replace(':', ''))

                        # Kiểm tra Timestamp Option (Kind = 8)
                        if b'\x08' in options_bytes:
                            tsval_index = options_bytes.find(b'\x08') + 2
                            tsval = int.from_bytes(options_bytes[tsval_index:tsval_index + 4], byteorder='big')

                            # Kiểm tra tín hiệu kết thúc
                            if tsval == termination_tsval:
                                print("Received termination signal. Stopping capture.")
                                break

                            # Thêm TSval hợp lệ vào danh sách
                            if tsval < (1 << 32):  # Chỉ nhận giá trị TSval hợp lệ
                                encrypted_message_chunks.append(tsval.to_bytes(4, 'big'))
                                print(f"Received chunk (TSval): {tsval}")
                            else:
                                print(f"Invalid TSval: {tsval}, skipping.")
                        else:
                            print("Timestamp option not found in this packet.")
                    else:
                        print("TCP Options field not found in this packet.")
        except Exception as e:
            print(f"Error processing packet: {e}")
except Exception as e:
    print(f"Error capturing packets: {e}")

# Kết hợp các phần của thông điệp mã hóa
try:
    encrypted_message = b''.join(encrypted_message_chunks).rstrip(b'\x00')  
    print(f"Combined encrypted message (bytes): {encrypted_message}")
except Exception as e:
    print(f"Failed to combine encrypted message: {e}")

# Hàm giải mã AES
def decrypt_aes(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = base64.b64decode(ciphertext)
    return unpad(cipher.decrypt(padded_message), AES.block_size).decode()

# Giải mã thông điệp
if encrypted_message:
    try:
        decoded_message = decrypt_aes(derived_key, encrypted_message)
        print(f"Decoded message: {decoded_message}")
    except Exception as e:
        print(f"Failed to decode message: {e}")
    finally:
        # Xóa các khóa nhạy cảm khỏi bộ nhớ
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(bytearray(derived_key))), 0, len(derived_key))
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(bytearray(shared_key))), 0, len(shared_key))
        del private_key, public_key
        print("Sensitive keys cleared from memory.")
else:
    print("No encrypted message received.")