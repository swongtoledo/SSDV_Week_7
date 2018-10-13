import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


client = socket.socket()
ip = socket.gethostbyname(socket.gethostname())
port = 9500
address = (ip,port)

client.connect(address)

##gnerate key
key = RSA.generate(2048)
privateKey = key.exportKey()
file1 = open('keyfile.pem', 'wb')
file1.write(privateKey)
file1.close()




def communicate(data):
    

    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("receiver.pem").read())
    session_key = get_random_bytes(16)  

# Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    return


communicate("Hello this is a message.".encode("utf-8"))




