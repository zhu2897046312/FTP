import os
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import getpass
import bcrypt

class FTPClient:
    def __init__(self, host='127.0.0.1', port=2121):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes_key = None
        self.cipher_aes = None
        self.nonce = None
        
    def connect(self):
        self.client_socket.connect((self.host, self.port))
        
        # 接收服务器公钥
        server_public_key = RSA.import_key(self.client_socket.recv(1024))
        
        # 生成并发送AES密钥
        self.aes_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(server_public_key)
        enc_aes_key = cipher_rsa.encrypt(self.aes_key)
        self.client_socket.sendall(enc_aes_key)
        
        # 接收AES nonce
        self.nonce = self.client_socket.recv(16)
        self.cipher_aes = AES.new(self.aes_key, AES.MODE_EAX, nonce=self.nonce)
        
        # 用户认证
        if not self.authenticate():
            print("Authentication failed")
            return False
        return True

    # 加密/解密方法
    def encrypt_data(self, data):
        return self.cipher_aes.encrypt(data)

    def decrypt_data(self, data):
        return self.cipher_aes.decrypt(data)

    # 用户认证
    def authenticate(self):
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        creds = f"{username}:{password}"
        enc_creds = self.encrypt_data(creds.encode())
        self.client_socket.sendall(enc_creds)
        
        response = self.decrypt_data(self.client_socket.recv(1024)).decode()
        return response == "AUTH_SUCCESS"

    # 命令处理
    def send_command(self, command):
        enc_cmd = self.encrypt_data(command.encode())
        self.client_socket.sendall(enc_cmd)
        
        enc_response = self.client_socket.recv(1024)
        response = self.decrypt_data(enc_response).decode()
        print(response)

    def start_cli(self):
        while True:
            try:
                cmd = input("ftp> ")
                if cmd.lower() == 'exit':
                    break
                self.send_command(cmd)
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    client = FTPClient()
    if client.connect():
        print("Connected successfully")
        client.start_cli()
    client.client_socket.close()