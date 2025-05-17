from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
import base64

def generate_dh_shared_key():
    receiver_priv = ECC.generate(curve='P-256')
    sender_priv = ECC.generate(curve='P-256')
    receiver_pub = receiver_priv.public_key()
    sender_pub = sender_priv.public_key()
    shared_secret_receiver = receiver_priv.d * sender_pub.pointQ
    shared_secret_sender = sender_priv.d * receiver_pub.pointQ

    def derive_key(shared_point):
        x = int(shared_point.x)
        raw = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
        return HKDF(master=raw, key_len=16, salt=None, hashmod=SHA256, context=b'', num_keys=1)

    shared_key = derive_key(shared_secret_receiver)
    return shared_key, receiver_pub, sender_pub

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.publickey(), key

def generate_keys_encrypt(plain_text):
    shared_aes_key, receiver_dh_pub, sender_dh_pub = generate_dh_shared_key()
    rsa_pub, rsa_priv = generate_rsa_keys()
    aes_cipher = AES.new(shared_aes_key, AES.MODE_EAX)
    ct1, tag = aes_cipher.encrypt_and_digest(plain_text.encode())
    rsa_cipher = PKCS1_OAEP.new(rsa_pub)
    combined = shared_aes_key + ct1
    ct2 = rsa_cipher.encrypt(combined)
    return {
        "ct2": base64.b64encode(ct2).decode(),
        "public_key": rsa_pub.export_key().decode(),
        "private_key": rsa_priv.export_key().decode(),
        "nonce": base64.b64encode(aes_cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def decrypt_ct2_to_ct1(ct2_b64, private_key_pem):
    try:
        ct2 = base64.b64decode(ct2_b64)
        private_key = RSA.import_key(private_key_pem)
        rsa_decipher = PKCS1_OAEP.new(private_key)
        decrypted = rsa_decipher.decrypt(ct2)
        aes_key = decrypted[:16]
        ct1 = decrypted[16:]
        return {
            "ct1": base64.b64encode(ct1).decode(),
            "aes_key_recovered": base64.b64encode(aes_key).decode(),
            "success_ct2": True
        }
    except:
        return {"error_ct2": "❌ CT2 decryption failed. Invalid private key or CT2."}

def decrypt_ct1_to_pt(ct1_b64, aes_key_b64, nonce_b64, tag_b64):
    try:
        ct1 = base64.b64decode(ct1_b64)
        aes_key = base64.b64decode(aes_key_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        pt = aes_cipher.decrypt_and_verify(ct1, tag).decode()
        return {"decrypted": pt, "success_ct1": True}
    except:
        return {"error_ct1": "❌ Final decryption failed. Invalid AES secret key or CT1."}
