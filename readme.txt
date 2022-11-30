Authors:
    Itzhak Rahamim - 312202351
    Gil Ben Hamo - 315744557
    Yovel Aloni - 319122842

Description:
    This project is a simple client server connection using ECDH key exchange and RSA encryption.
    Socket:
        Create simple tcp connection for client server.
    Key exchange with ECDH:
        - Generate private and public key for both sides.
        - Each side send his public key to the other, so they can make shared key.
    Encryption with AES:
        - The client send text to the server.
        - The server will encrypt the text and send it to the client.
        - The client will decrypt the message.

Requirements:
    - Python 3.9 (or above)
    - Make sure you install all packages listed on "requirements.txt"

