from scapy.all import *
from decimal import Decimal


pcap_file = "captureICMP.pcapng"
destination_ip = "10.11.12.10"
special_ttl = 99


packets = rdpcap(pcap_file)

# Danh sách thời gian của gói tin hợp lệ
timestamps = []

# Lọc gói tin có IP.dst = 10.11.12.10 và TTL = 99
print("Filtering packets...")
for i, packet in enumerate(packets):
    if packet.haslayer(ICMP) and packet[IP].dst == destination_ip and packet[IP].ttl == special_ttl:
        timestamps.append(packet.time)
        print(f"Packet #{i+1}: Time={packet.time}, IP.dst={packet[IP].dst}, TTL={packet[IP].ttl}")

# Tính khoảng thời gian giữa các gói tin hợp lệ 
time_deltas = [round(float(timestamps[i] - timestamps[i-1]), 3) for i in range(1, len(timestamps))]
print("Filtered Delta times:", time_deltas)

# Từ điển quy ước thời gian với từng ký tự
timing_dict = {
    0.1: "A", 0.2: "B", 0.3: "C", 0.4: "D", 0.5: "E", 0.6: "F", 0.7: "G", 0.8: "H",
    0.9: "I", 1.0: "J", 1.1: "K", 1.2: "L", 1.3: "M", 1.4: "N", 1.5: "O", 1.6: "P",
    1.7: "Q", 1.8: "R", 1.9: "S", 2.0: "T", 2.1: "U", 2.2: "V", 2.3: "W", 2.4: "X",
    2.5: "Y", 2.6: "Z",
    2.7: "0", 2.8: "1", 2.9: "2", 3.0: "3", 3.1: "4", 3.2: "5", 3.3: "6", 3.4: "7",
    3.5: "8", 3.6: "9",
    3.7: " ", 3.8: ",", 3.9: ".", 4.0: "?", 4.1: "!", 4.2: ":", 4.3: ";", 4.4: "-",
    4.5: "(", 4.6: ")", 4.7: "'", 4.8: "\"", 4.9: "/", 5.0: "\\", 5.1: "_", 5.2: "@",
    5.3: "#", 5.4: "$", 5.5: "%", 5.6: "^", 5.7: "&", 5.8: "*", 5.9: "+", 6.0: "="
}

# Hàm khớp gần đúng
def get_approx_char(delta, timing_dict, threshold=0.5):
    closest_key = None
    smallest_diff = float('inf')
    for key in timing_dict:
        diff = abs(delta - key)
        if diff < smallest_diff:
            smallest_diff = diff
            closest_key = key
    print(f"Delta: {delta}, Closest timing_dict key: {closest_key}, Difference: {smallest_diff}")
    if smallest_diff <= threshold:
        return timing_dict[closest_key]
    print(f"Delta {delta} không khớp với bất kỳ ký tự nào.")
    return "?"

# Giải mã thông điệp từ delta times
decoded_message = ""
print("Matching deltas to timing_dict:")
for delta in time_deltas:
    matched_char = get_approx_char(delta, timing_dict)
    decoded_message += matched_char
    print(f"Delta: {delta}, Matched character: {matched_char}")

print("Decoded message:", decoded_message)