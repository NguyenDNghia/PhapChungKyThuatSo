import time
from scapy.all import *

# Thông điệp cần giấu
message = "HELLO, HOW ARE YOU? :)"

# Quy ước thời gian giữa các gói tin cho từng ký tự
timing_dict = {
    "A": 0.1, "B": 0.2, "C": 0.3, "D": 0.4, "E": 0.5, "F": 0.6, "G": 0.7, "H": 0.8,
    "I": 0.9, "J": 1.0, "K": 1.1, "L": 1.2, "M": 1.3, "N": 1.4, "O": 1.5, "P": 1.6,
    "Q": 1.7, "R": 1.8, "S": 1.9, "T": 2.0, "U": 2.1, "V": 2.2, "W": 2.3, "X": 2.4,
    "Y": 2.5, "Z": 2.6,
    "0": 2.7, "1": 2.8, "2": 2.9, "3": 3.0, "4": 3.1, "5": 3.2, "6": 3.3, "7": 3.4,
    "8": 3.5, "9": 3.6,
    " ": 3.7, ",": 3.8, ".": 3.9, "?": 4.0, "!": 4.1, ":": 4.2, ";": 4.3, "-": 4.4,
    "(": 4.5, ")": 4.6, "'": 4.7, "\"": 4.8, "/": 4.9, "\\": 5.0, "_": 5.1, "@": 5.2,
    "#": 5.3, "$": 5.4, "%": 5.5, "^": 5.6, "&": 5.7, "*": 5.8, "+": 5.9, "=": 6.0
}

# Địa chỉ IP đích
destination_ip = "10.11.12.10"
special_ttl = 99  # TTL đặc biệt để giúp nhận diện gói tin chứa thông điệp giấu

# Gửi từng ký tự 
for char in message:
    if char in timing_dict:
        # Tạo gói tin ICMP Echo Request 
        packet = IP(dst=destination_ip, ttl=special_ttl) / ICMP()
        # Gửi gói tin
        send(packet, verbose=0)
        print(f"Sent '{char}' with delay {timing_dict[char]} seconds")
        # Dừng một khoảng thời gian tương ứng với ký tự
        time.sleep(timing_dict[char])
    else:
        print(f"Character '{char}' không được hỗ trợ trong timing_dict.")

print("Thông điệp đã được gửi qua Timing Channel.")