from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

# Fungsi untuk mengenkripsi data
def encrypt_aes(plain_text, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    encrypted_data = base64.b64encode(iv + encrypted_bytes).decode('utf-8')
    return encrypted_data

# Fungsi untuk mendekripsi data
def decrypt_aes(encrypted_data, key):
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_data_bytes[:16]
    encrypted_bytes = encrypted_data_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    decrypted_text = decrypted_bytes.decode('utf-8')
    return decrypted_text

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form['action']
        text = request.form['text']
        key = request.form['key'].encode()

        if len(key) not in [16, 24, 32]:
            return render_template('index.html', result="Key harus sepanjang 16, 24, atau 32 karakter!")

        if action == 'encrypt':
            result = encrypt_aes(text, key)
        elif action == 'decrypt':
            try:
                result = decrypt_aes(text, key)
            except Exception as e:
                result = "Kesalahan saat dekripsi: " + str(e)

        return render_template('index.html', result=result)

    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
