
import socket
import os

print("[+] Connecting to the server")
server_address = ('localhost', 8345)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)
print("[+] Connection successful!")

key = bytes.fromhex('6574212c9b4d9334d893bec2477cb86a70983b3c33952d68a8cc5c0226070abf')
nonce = bytes.fromhex('0e02f4a9a8b5beeaba8348d6d2f87c606849df9a5eef49a65c98cf07d4c238a6')

client_socket.send(key)
ack_k = client_socket.recv(12)
print("[+] Key exchange result %s" % ack_k)

client_socket.send(nonce)
ack_n = client_socket.recv(12)
print("[+] Nonce exchange result %s" % ack_n)

upload_cmd = b'upload C:\output\wall.png 122218\x0D\x0A'
client_socket.send(upload_cmd)
print("[+] Upload cmd sent")
upload_result = client_socket.recv(12)
print("[+] Upload cmd result %s" % upload_result)

file_path = "wall.png"
data = None

try:
    with open(file_path, 'rb') as file:
        data = file.read()
        client_socket.send(data)
        upload_result = client_socket.recv(12)
        print("[+] Upload binary result %s", upload_result)
except FileNotFoundError:
    print(f"File '{file_path}' not found.")
except Exception as e:
    print(f"An error occurred: {str(e)}")

client_socket.close()