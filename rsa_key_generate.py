from Crypto.PublicKey import RSA

def generate_keys(role):
    # 生成2048位的RSA密钥对
    key = RSA.generate(2048)
    
    # 私钥
    private_key = key.export_key()
    private_key_filename = f"{role}_private_key.pem"
    with open(private_key_filename, "wb") as priv_file:
        priv_file.write(private_key)
    
    # 公钥
    public_key = key.publickey().export_key()
    public_key_filename = f"{role}_public_key.pem"
    with open(public_key_filename, "wb") as pub_file:
        pub_file.write(public_key)

    print(f"{role.capitalize()} keys generated and saved to {private_key_filename} and {public_key_filename}.")

if __name__ == "__main__":
    generate_keys("sender")
    generate_keys("receiver")
