from flask import Flask, render_template, request, session
from crypto_logic import generate_keys_encrypt, decrypt_ct2_to_ct1, decrypt_ct1_to_pt
import base64

app = Flask(__name__)
app.secret_key = "super_secure_demo_key"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = {}
    if request.method == 'POST':
        action = request.form.get('action')

        if action == "encrypt":
            plain_text = request.form.get("plain_text")
            result = generate_keys_encrypt(plain_text)
            session["ct2"] = result["ct2"]
            session["public_key"] = result["public_key"]
            session["private_key"] = result["private_key"]
            session["nonce"] = result["nonce"]
            session["tag"] = result["tag"]

        elif action == "ct2_decrypt":
            ct2 = request.form.get("ct2")
            private_key = request.form.get("private_key")
            result = decrypt_ct2_to_ct1(ct2, private_key)
            if "ct1" in result:
                session["ct1"] = result["ct1"]
                session["aes_key_recovered"] = result["aes_key_recovered"]

        elif action == "ct1_decrypt":
            ct1 = request.form.get("ct1")
            aes_key = request.form.get("aes_key")
            nonce = session.get("nonce")
            tag = session.get("tag")
            result = decrypt_ct1_to_pt(ct1, aes_key, nonce, tag)

    return render_template("index.html", result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5003)
