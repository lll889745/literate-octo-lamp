import socket
import zipfile
import ntplib
from io import BytesIO
from datetime import datetime
from tqdm import tqdm  # 进度条
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from os import urandom

'''加载密钥'''
with open("sender_private_key.pem", "rb") as key_file:
    sender_private_key = load_pem_private_key(key_file.read(), password=None)

with open("receiver_public_key.pem", "rb") as key_file:
    receiver_public_key = load_pem_public_key(key_file.read())

'''生成消息摘要'''
def generate_message_digest(data):
    digest = hashes.Hash(hashes.SHA256()) # 使用 SHA-256 算法创建一个哈希对象
    digest.update(data) # 更新哈希对象的状态，将 data 的内容添加到哈希中
    return digest.finalize() # 计算并返回最终的消息摘要

'''生成签名'''
def sign_message(private_key, message):
    return private_key.sign( #使用私钥对消息进行签名
        message, # 1. 要签名的消息
        asym_padding.PSS( # 2. 使用 PSS 填充方案
            mgf=asym_padding.MGF1(hashes.SHA256()), # (1) 使用 SHA-256 哈希算法的 MGF1
            salt_length=asym_padding.PSS.MAX_LENGTH # (2) 使用最大长度的盐值
        ),
        hashes.SHA256() # 3. 使用 SHA-256 哈希算法
    )

'''文件打包'''
def package_and_compress(filename): 
    with open(filename, "rb") as f: # 以二进制模式打开文件 + 读取文件内容
        original_data = f.read()

    # 获取签名
    signature = sign_message(sender_private_key, generate_message_digest(original_data))

    # 使用ntp库来获取网络时间
    ntp_client = ntplib.NTPClient()
    response = ntp_client.request('time.nist.gov')
    ntp_timestamp = response.tx_time
    # 格式化时间为 "YYYY-MM-DD HH:MM:SS"
    formatted_timestamp = datetime.fromtimestamp(ntp_timestamp).strftime('%Y-%m-%d %H:%M:%S').encode('utf-8')

    mem_file = BytesIO() # 创建一个 BytesIO 对象（内存中的二进制数据流）
    with zipfile.ZipFile(mem_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr('original_data', original_data) # 原始数据
        zipf.writestr('signature.txt', signature) # 身份验证 + 完整性校验
        zipf.writestr('timestamp.txt', formatted_timestamp) # 避免重放攻击

    # 直接从内存中读取数据，而不是从硬盘上的文件中读取
    mem_file.seek(0) # 将内存流的指针移动到文件开头
    return mem_file.getvalue() # 读取内存中的数据

'''加密数据'''
def encrypt_data(data, key):
    # 生成一个随机的 16 字节的随机数 IV 作为初始向量，用于 CBC 模式
    iv = urandom(16)
    # 使用 AES 算法和 CBC 模式创建一个 Cipher 对象
    # AES 是一种对称加密算法
    # CBC 是一种加密模式，可以使相同的明文块和相同的密钥生成不同的密文块
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # 创建一个加密器对象
    encryptor = cipher.encryptor()
    # 创建一个 PKCS7 填充器对象，用于将数据填充到 AES 块大小的倍数
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    # 使用填充器对数据进行填充
    padded_data = padder.update(data) + padder.finalize()
    # 使用加密器对填充后的数据进行加密
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted_data

'''加密会话密钥'''
def encrypt_key(key, public_key):
    return public_key.encrypt(
        key,
        asym_padding.OAEP( # 使用 OAEP 填充方案
            # 使用 SHA-256 哈希算法的 MGF1
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            # 指定哈希算法 SHA256
            algorithm=hashes.SHA256(),
            label=None
        )
    )

'''使用 TCP socket 传输'''
def send_data_over_socket(data, host, port=54321):
    total = len(data)  # 计算数据的总长度，用于进度条显示
    # 创建一个 TCP socket 对象
    # socket.AF_INET 表示使用 IPv4 地址族，socket.SOCK_STREAM 表示使用 TCP 协议
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port)) # 连接到指定的主机和端口
        # 连接成功后，使用 tqdm 进度条显示数据发送进度
        # unit='B' 表示单位为字节，unit_scale=True 表示自动调整单位，desc='Sending Data' 表示进度条的描述
        with tqdm(total=total, unit='B', unit_scale=True, desc='Sending Data') as pbar:
            # 循环分块发送数据，每次发送 4096 字节
            for i in range(0, total, 4096):
                # 计算本次发送的数据长度
                sent = sock.send(data[i:i+4096])
                # 更新进度条
                pbar.update(sent)
        print(f"Data sent successfully to {host}:{port}")


def main():
 
    file_path = "original_data.zip" # Change path here
    # 压缩并打包原始数据、签名和时间戳
    zip_content = package_and_compress(file_path)
    # 生成一个 32 字节的随机数作为会话密钥
    session_key = urandom(32)
    # 使用会话密钥加密压缩后的数据
    iv, encrypted_data = encrypt_data(zip_content, session_key)
    # 使用接收方的公钥加密会话密钥
    encrypted_session_key = encrypt_key(session_key, receiver_public_key) 
    # 将 IV、加密后的会话密钥和加密后的数据拼接在一起
    final_package = iv + encrypted_session_key + encrypted_data
    receiver_host = "192.168.31.112"  # IP address of the receiver
    send_data_over_socket(final_package, receiver_host)

if __name__ == "__main__":
    main()
