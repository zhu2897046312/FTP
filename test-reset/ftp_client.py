import os
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import getpass
import bcrypt

class FTPClient:
    def __init__(self, host='127.0.0.1', port=8081):
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

    def download_file(self, remote_filename, local_filename):
        # 发送GET命令
        enc_cmd = self.encrypt_data(f"GET {remote_filename}".encode())
        self.client_socket.sendall(enc_cmd)
        
        # 先接收文件大小
        enc_size = self.client_socket.recv(4)
        if not enc_size:
            print("错误: 未收到文件头")
            return
        file_size = int.from_bytes(self.decrypt_data(enc_size), byteorder='big')
        
        # 接收文件数据
        received = 0
        with open(local_filename, 'wb') as f:
            while received < file_size:
                enc_chunk = self.client_socket.recv(1024)
                if not enc_chunk:
                    break
                chunk = self.decrypt_data(enc_chunk)
                f.write(chunk)
                received += len(chunk)
        
        if received == file_size:
            print(f"文件 {remote_filename} 下载成功")
        else:
            print(f"错误: 文件下载不完整")

    def upload_file(self, local_filename, remote_filename):
        # 检查本地文件是否存在
        if not os.path.isfile('E:\\WorkSpace\\FTP\\test-reset\\example.txt'):
            print(f"错误: 文件 {local_filename} 不存在")
            return
        
        # 发送PUT命令
        enc_cmd = self.encrypt_data(f"PUT {remote_filename}".encode())
        self.client_socket.sendall(enc_cmd)
        
        # 等待服务器响应
        enc_response = self.client_socket.recv(1024)
        response = self.decrypt_data(enc_response).decode()
        print(f"{response}")
        if response != "READY":
            print(f"错误: {response}")
            return
        
        # 读取并发送文件数据
        with open('E:\\WorkSpace\\FTP\\test-reset\\example.txt', 'rb') as f:
            file_data = f.read()
        file_size = len(file_data)
        enc_file_size = self.encrypt_data(file_size.to_bytes(4, byteorder='big'))
        self.client_socket.sendall(enc_file_size)

        # 分块发送数据
        chunk_size = 1024
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            enc_chunk = self.encrypt_data(chunk)
            self.client_socket.sendall(enc_chunk)
        
        # 接收最终响应
        enc_final_response = self.client_socket.recv(1024)
        final_response = self.decrypt_data(enc_final_response).decode()
        print(final_response)

    def start_cli(self):
        while True:
            try:
                cmd = input("ftp> ")
                if cmd.lower() == 'exit':
                    break
                elif cmd.startswith("get "):
                    parts = cmd.split()
                    if len(parts) != 2:
                        print("用法: get <远程文件名>")
                        continue
                    remote_file = parts[1]
                    local_file = os.path.basename(remote_file)
                    self.download_file(remote_file, local_file)
                elif cmd.startswith("put "):
                    parts = cmd.split()
                    if len(parts) != 3:
                        print("用法: put <本地文件名> <远程文件名>")
                        continue
                    local_file = parts[1]
                    remote_file = parts[2]
                    self.upload_file(local_file, remote_file)
                else:
                    enc_cmd = self.encrypt_data(cmd.encode())
                    self.client_socket.sendall(enc_cmd)
                    enc_response = self.client_socket.recv(1024)
                    response = self.decrypt_data(enc_response).decode()
                    print(response)
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    client = FTPClient()
    if client.connect():
        print("Connected successfully")
        client.start_cli()
    client.client_socket.close()