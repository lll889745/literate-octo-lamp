import socket
import zipfile
import ntplib
from io import BytesIO
from datetime import datetime
from tqdm import tqdm
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Load keys
with open("receiver_private_key.pem", "rb") as key_file:
    receiver_private_key = load_pem_private_key(key_file.read(), password=None)  # 私钥未被加密

with open("sender_public_key.pem", "rb") as key_file:
    sender_public_key = load_pem_public_key(key_file.read())

def generate_message_digest(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def decrypt_session_key(encrypted_session_key, private_key):
    return private_key.decrypt(
        encrypted_session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_data(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    # 解密并对可能的最后一块进行特殊处理
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    # 去填充
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()  # 去填充，finalize()去除可能的最后一块
    return decrypted_data

def decompress_and_verify(decrypted_data):
    # 打开内存中的zip文件
    mem_file = BytesIO(decrypted_data)
    with zipfile.ZipFile(mem_file, 'r') as zipf:
        original_data = zipf.read('original_data')
        signature = zipf.read('signature.txt')
        received_timestamp = zipf.read('timestamp.txt').decode('utf-8')
        # 获取当前时间
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request('time.nist.gov')
        current_ntp_time = response.tx_time
        formatted_current_timestamp = datetime.fromtimestamp(current_ntp_time).strftime('%Y-%m-%d %H:%M:%S')
        print(f"\nTimestamp from the sender: {received_timestamp}")
        print(f"Current time on the receiver: {formatted_current_timestamp}")
        # 验证时间戳，防止重放攻击
        received_time_seconds = datetime.strptime(received_timestamp, '%Y-%m-%d %H:%M:%S').timestamp()
        time_difference = current_ntp_time - received_time_seconds
        print(f"Time difference: {time_difference} seconds")
        if time_difference > 300:
            print("Potential replay attack detected.")
            raise Exception("Timestamp validation failed. Potential replay attack.")
        # 验证签名
        try:
            sender_public_key.verify(
                signature,
                generate_message_digest(original_data),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verified successfully.")
            return original_data
        except InvalidSignature:
            print("Signature verification failed.")
            return None

def receive_data_over_socket(host='0.0.0.0', port=54321):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, port))
        sock.listen()
        print(f"Listening for incoming connections on {host}:{port}")
        # 当有连接到达时，会返回一个新的套接字对象和地址
        conn, addr = sock.accept()
        with conn:
            print('Connected by', addr)
            full_data = bytearray() # 创建空字节数组，用于存储接收到的数据
            # 使用 tqdm 进度条显示接收数据的进度
            with tqdm(unit='B', unit_scale=True, desc='Receiving Data') as pbar:
                while True:
                    chunk = conn.recv(4096)
                    # 如果没有数据，退出循环
                    if not chunk:
                        break
                    # 将接收到的数据添加到字节数组 full_data 中
                    full_data.extend(chunk)
                    pbar.update(len(chunk))
            # 将字节数组转换为字节串，并提取 IV、加密的会话密钥和加密的数据
            full_data_bytes = bytes(full_data)
            iv = full_data_bytes[:16]
            encrypted_session_key = full_data_bytes[16:272]
            encrypted_data = full_data_bytes[272:]
            session_key = decrypt_session_key(encrypted_session_key, receiver_private_key)
            decrypted_data = decrypt_data(encrypted_data, session_key, iv)
            result = decompress_and_verify(decrypted_data)
            # 如果验证成功，将数据保存到文件
            if result:
                save_path = 'received_file.zip'
                with open(save_path, 'wb') as file:
                    file.write(result)
                print(f"\nFile saved to {save_path}")

if __name__ == "__main__":
    receive_data_over_socket()
