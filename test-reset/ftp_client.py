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
        self.encrypt_cipher = None
        self.decrypt_cipher = None
        
    def connect(self):
        self.client_socket.connect((self.host, self.port))
        
        # 接收服务器公钥
        server_public_key = RSA.import_key(self.client_socket.recv(1024))
        
        # 生成并发送AES密钥
        self.aes_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(server_public_key)
        enc_aes_key = cipher_rsa.encrypt(self.aes_key)
        self.client_socket.sendall(enc_aes_key)
        
        # 接收AES nonce并初始化两个cipher实例
        self.nonce = self.client_socket.recv(16)
        self.encrypt_cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce=self.nonce)
        self.decrypt_cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce=self.nonce)

        # 用户认证
        if not self.authenticate():
            print("Authentication failed")
            return False
        return True

    # 加密/解密方法
    def encrypt_data(self, data):
        return self.encrypt_cipher.encrypt(data)

    def decrypt_data(self, data):
        return self.decrypt_cipher.decrypt(data)

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
        cmd_parts = command.split()
        cmd = cmd_parts[0].upper() if cmd_parts else ""
        
        # 特殊处理GET和PUT命令
        if cmd == "GET" and len(cmd_parts) > 1:
            return self.download_file(cmd_parts[1])
        elif cmd == "PUT" and len(cmd_parts) > 1:
            return self.upload_file(cmd_parts[1])
            
        # 其他命令的常规处理
        enc_cmd = self.encrypt_data(command.encode())
        self.client_socket.sendall(enc_cmd)
        
        enc_response = self.client_socket.recv(1024)
        response = self.decrypt_data(enc_response).decode()
        print(response)

    def download_file(self, filename):
        # 发送GET命令
        command = f"GET {filename}"
        enc_cmd = self.encrypt_data(command.encode())
        self.client_socket.sendall(enc_cmd)
        
        # 接收文件大小
        enc_size = self.client_socket.recv(1024)
        size = int(self.decrypt_data(enc_size).decode())
        
        # 发送准备就绪确认
        ready_msg = "READY".encode()
        enc_ready = self.encrypt_data(ready_msg)
        self.client_socket.sendall(enc_ready)
        
        # 接收并保存文件
        try:
            with open(filename, 'wb') as f:
                received_size = 0
                while received_size < size:
                    chunk_size = min(8192, size - received_size)
                    enc_chunk = self.client_socket.recv(chunk_size)
                    chunk = self.decrypt_data(enc_chunk)
                    f.write(chunk)
                    received_size += len(chunk)
            print(f"文件 {filename} 下载成功")
        except Exception as e:
            print(f"下载失败: {str(e)}")

    def upload_file(self, filename):
        if not os.path.exists(filename):
            print("错误: 文件不存在")
            return
            
        try:
            # 发送PUT命令
            command = f"PUT {filename}"
            enc_cmd = self.encrypt_data(command.encode())
            self.client_socket.sendall(enc_cmd)
            
            # 读取文件并发送大小
            with open(filename, 'rb') as f:
                file_data = f.read()
            size_msg = str(len(file_data)).encode()
            enc_size = self.encrypt_data(size_msg)
            self.client_socket.sendall(enc_size)
            
            # 等待服务器确认
            enc_confirm = self.client_socket.recv(1024)
            confirm = self.decrypt_data(enc_confirm).decode()
            
            if confirm == "READY":
                # 分块发送文件
                chunk_size = 8192
                for i in range(0, len(file_data), chunk_size):
                    chunk = file_data[i:i + chunk_size]
                    enc_chunk = self.encrypt_data(chunk)
                    self.client_socket.sendall(enc_chunk)
                
                # 接收上传完成响应
                enc_response = self.client_socket.recv(1024)
                response = self.decrypt_data(enc_response).decode()
                print(response)
        except Exception as e:
            print(f"上传失败: {str(e)}")
            
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