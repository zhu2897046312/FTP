import os
import sys
import sqlite3
import socket
import threading
import time
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
    def __init__(self, host='0.0.0.0', port=8081):
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
            print(f"正在进行用户认证")
            if not self.authenticate(client_socket, encrypt_cipher,creds):  # 调用认证方法
                print("Authentication failed for client. Closing connection.")
                client_socket.close()
                return
            print(f"认证完成")

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
    def authenticate(self, client_socket, cipher,creds):
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
            if cmd == "GET":
                if len(args) != 1:
                    response = "错误: 请指定文件名"
                    self.send_response(client_socket, response, cipher)
                else:
                    filename = args[0]
                    filepath = os.path.join(self.current_dir, filename)
                    if os.path.isfile(filepath):
                        try:
                            with open(filepath, 'rb') as f:
                                file_data = f.read()
                            # 先发送文件大小（4字节头）
                            file_size = len(file_data).to_bytes(4, byteorder='big')
                            client_socket.sendall(cipher.encrypt(file_size))
                            # 再分块发送文件数据
                            chunk_size = 1024
                            for i in range(0, len(file_data), chunk_size):
                                chunk = file_data[i:i+chunk_size]
                                client_socket.sendall(cipher.encrypt(chunk))
                        except Exception as e:
                            response = f"错误: {str(e)}"
                            self.send_response(client_socket, response, cipher)
                    else:
                        response = "错误: 文件不存在"
                        self.send_response(client_socket, response, cipher)
            elif cmd == "PUT":
                if len(args) != 1:
                    response = "错误: 请指定远程文件名"
                    self.send_response(client_socket, response, cipher)
                else:
                    remote_filename = args[0]
                    # 发送READY信号
                    self.send_response(client_socket, "READY", cipher)
                    # 接收文件数据
                    enc_data = client_socket.recv(1024 * 1024)  # 假设文件较小
                    file_data = self.decrypt_data(enc_data, cipher)
                    filepath = os.path.join(self.current_dir, remote_filename)
                    try:
                        with open(filepath, 'wb') as f:
                            f.write(file_data)
                        response = f"文件 {remote_filename} 上传成功"
                    except Exception as e:
                        response = f"错误: {str(e)}"
                    self.send_response(client_socket, response, cipher)
            elif cmd == "LIST":
                files = os.listdir(self.current_dir)
                response = "\n".join(files)
            elif cmd == "PWD":
                response = self.current_dir
            elif cmd == "CD":
                if not args:
                    response = "错误: 请指定目录路径"
                else:
                    target_dir = args[0]
                    if target_dir == "..":
                        new_dir = os.path.dirname(self.current_dir)
                    else:
                        new_dir = os.path.join(self.current_dir, target_dir)
                    
                    if os.path.exists(new_dir) and os.path.isdir(new_dir):
                        self.current_dir = os.path.abspath(new_dir)
                        response = f"当前目录已更改为: {self.current_dir}"
                    else:
                        response = "错误: 目录不存在"
            elif cmd == "MKDIR":
                if not args:
                    response = "错误: 请指定目录名"
                else:
                    new_dir = os.path.join(self.current_dir, args[0])
                    try:
                        os.makedirs(new_dir)
                        response = f"目录创建成功: {args[0]}"
                    except FileExistsError:
                        response = "错误: 目录已存在"
                    except Exception as e:
                        response = f"创建目录失败: {str(e)}"
            elif cmd == "CREATE":
                if not args:
                    response = "错误: 请指定文件名"
                else:
                    file_path = os.path.join(self.current_dir, args[0])
                    try:
                        with open(file_path, 'w') as f:
                            if len(args) > 1:
                                f.write(' '.join(args[1:]))
                        response = f"文件创建成功: {args[0]}"
                    except Exception as e:
                        response = f"创建文件失败: {str(e)}"
            elif cmd == "RENAME":
                if len(args) != 2:
                    response = "错误: 请指定源文件/目录名和目标名"
                else:
                    old_path = os.path.join(self.current_dir, args[0])
                    new_path = os.path.join(self.current_dir, args[1])
                    if os.path.exists(old_path):
                        try:
                            os.rename(old_path, new_path)
                            response = f"重命名成功: {args[0]} -> {args[1]}"
                        except Exception as e:
                            response = f"重命名失败: {str(e)}"
                    else:
                        response = "错误: 源文件/目录不存在"
            elif cmd == "ATTRIB":
                if not args:
                    response = "错误: 请指定文件/目录名"
                else:
                    path = os.path.join(self.current_dir, args[0])
                    if os.path.exists(path):
                        try:
                            stat = os.stat(path)
                            is_dir = os.path.isdir(path)
                            mode = stat.st_mode
                            size = stat.st_size if not is_dir else '-'
                            mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
                            
                            attr_info = [
                                f"{'目录' if is_dir else '文件'}: {args[0]}",
                                f"大小: {size} 字节",
                                f"修改时间: {mtime}",
                                f"权限: {oct(mode)[-3:]}",
                                f"只读: {'是' if not os.access(path, os.W_OK) else '否'}"
                            ]
                            response = "\n".join(attr_info)
                        except Exception as e:
                            response = f"获取属性失败: {str(e)}"
                    else:
                        response = "错误: 文件/目录不存在"
            elif cmd == "ADD":
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
            else:
                response = f"错误: 未知命令 '{cmd}'\n可用命令: LIST, PWD, CD, MKDIR, RENAME, ATTRIB, ADD"
            
            self.send_response(client_socket, response, cipher)
        except Exception as e:
            self.send_response(client_socket, f"ERROR: {str(e)}", cipher)

    def send_response(self, client_socket, response, cipher):
        enc_response = cipher.encrypt(response.encode())
        client_socket.sendall(enc_response)

if __name__ == "__main__":
    server = FTPServer()
    server.start()