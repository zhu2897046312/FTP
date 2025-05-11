import os
import sys
import sqlite3
import socket
import threading
import mysql.connector
from mysql.connector import Error
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import hashlib
import bcrypt

# 数据库初始化
conn = sqlite3.connect('ftp_users.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT)''')
conn.commit()
# MySQL 数据库配置
DB_CONFIG = {
    'host': '172.25.13.23',
    'user': 'root',
    'password': '123',
    'database': 'ftp_db'
}

class FTPServer:
    def __init__(self, host='0.0.0.0', port=2121):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.current_dir = os.getcwd()
         # 初始化数据库
        self.init_db()
        # 生成RSA密钥对
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey().export_key()
        self.private_key = self.rsa_key.export_key()
    
    def init_db(self):
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL
                )
            ''')
            conn.commit()
            print(f"Database connect successfully!!")
        except Error as e:
            print(f"Database error: {e}")
            sys.exit(1)
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
        # 添加默认用户 admin / 123456（如果不存在）
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            if cursor.fetchone() is None:
                default_password = '123456'
                password_hash = bcrypt.hashpw(default_password.encode(), bcrypt.gensalt()).decode()
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    ('admin', password_hash)
                )
                conn.commit()
                print("Default user 'admin' created.")
            else:
                print("Default user 'admin' already exists.")
        except Error as e:
            print(f"Error inserting default user: {e}")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"FTP Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"New connection from {addr}")
            client_handler = threading.Thread(
                target=self.handle_client,
                args=(client_socket,)
            )
            client_handler.start()

    def handle_client(self, client_socket):
        try:
            # 发送公钥给客户端
            client_socket.sendall(self.public_key)
            
            # 接收加密的AES密钥
            enc_aes_key = client_socket.recv(256)
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
            aes_key = cipher_rsa.decrypt(enc_aes_key)
            
            # 生成nonce并初始化加密和解密的cipher
            nonce = get_random_bytes(16)
            client_socket.sendall(nonce)
            encrypt_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypt_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)

            # 用户认证使用decrypt_cipher解密
            enc_creds = client_socket.recv(1024)
            creds = self.decrypt_data(enc_creds, decrypt_cipher).decode().split(':')

            # 发送响应使用encrypt_cipher加密
            self.send_response(client_socket, "AUTH_SUCCESS", encrypt_cipher)

            # 处理命令循环
            while True:
                enc_data = client_socket.recv(1024)
                data = self.decrypt_data(enc_data, decrypt_cipher).decode()
                # 处理命令并发送响应使用encrypt_cipher
                self.process_command(data, client_socket, encrypt_cipher)
                
        finally:
            client_socket.close()

    # 加密/解密方法
    def encrypt_data(self, data, cipher):
        return cipher.encrypt(data)

    def decrypt_data(self, data, cipher):
        return cipher.decrypt(data)

    # 用户认证
    def authenticate(self, client_socket, cipher):
        enc_creds = client_socket.recv(1024)
        creds = self.decrypt_data(enc_creds, cipher).decode().split(':')
        username, password = creds[0], creds[1]
        
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            
            if result and bcrypt.checkpw(password.encode(), result[0].encode()):
                self.send_response(client_socket, "AUTH_SUCCESS", cipher)
                return True
            else:
                self.send_response(client_socket, "AUTH_FAILED", cipher)
                return False
        except Error as e:
            print(f"Database error: {e}")
            return False
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    # 命令处理
    def process_command(self, command, client_socket, cipher):
        cmd_parts = command.split()
        if not cmd_parts:
            return
            
        cmd = cmd_parts[0].upper()
        args = cmd_parts[1:] if len(cmd_parts) > 1 else []
        
        response = ""
        try:
            if cmd == "LIST":
                files = os.listdir(self.current_dir)
                response = "\n".join(files)
            elif cmd == "PWD":
                response = self.current_dir
            if cmd == "ADD":
                if len(args) != 2:
                    raise ValueError("Usage: add <username> <password>")
                
                username = args[0]
                password = args[1]
                password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                
                try:
                    conn = mysql.connector.connect(**DB_CONFIG)
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                        (username, password_hash)
                    )
                    conn.commit()
                    self.send_response(client_socket, "User added successfully", cipher)
                except mysql.connector.IntegrityError:
                    self.send_response(client_socket, "Error: Username already exists", cipher)
                finally:
                    if conn.is_connected():
                        cursor.close()
                        conn.close()
            
            self.send_response(client_socket, response, cipher)
        except Exception as e:
            self.send_response(client_socket, f"ERROR: {str(e)}", cipher)

    def send_response(self, client_socket, response, cipher):
        enc_response = cipher.encrypt(response.encode())
        client_socket.sendall(enc_response)

if __name__ == "__main__":
    server = FTPServer()
    server.start()