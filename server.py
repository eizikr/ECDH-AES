import random
import socket
from tinyec import registry
from extra import compress
import secrets
import pickle
from Crypto.Cipher import AES


HOST = socket.gethostname()  # Default loopback
PORT = 5000  # Port number
#Gettin al the curves types
CURVES = list(registry.EC_CURVE_REGISTRY.keys())

def server_program():
    
    #--------- Create handshake with clients ---------
    server_socket = socket.socket()  # Instance of socket
    server_socket.bind((HOST, PORT))  
    server_socket.listen(1) # Configure how many client the server can listen
    connection, address = server_socket.accept()
    print("--------------------------------------------------")
    print("Connection from: " + str(address) + " is open")
    print("--------------------------------------------------")

    #----------- End handshake with clients -----------
    

    # ------------ Key exchange - ECDE ----------------
    startKEmsg = connection.recv(1024).decode()
    if(startKEmsg != 'StartKE'):
        print('Incorrect message recived')
        exit()

    # curve_str = CURVES[0] # later random!!
    curve_str = random.choice(CURVES) # later random!!
    connection.send(curve_str.encode())  # Send Curve to the client
    
    ## get client public key
    clientPubKey = pickle.loads(connection.recv(1024))
    
    ## server keys creation
    curve = registry.get_curve(curve_str)
    serverPrivKey = secrets.randbelow(curve.field.n)
    serverPubKey = serverPrivKey * curve.g
    
    ## send public key to client
    serverPubKey_asBytes = pickle.dumps(serverPubKey)
    connection.send(serverPubKey_asBytes)  # Send message to the client
    
    ## create shared key
    sharedKey = serverPrivKey * clientPubKey
    # ----------- END key exchange - ECDE ----------------

    while True:
        # ----- AES object init section -----
        cipher = AES.new(bytes(compress(sharedKey), 'utf-8'), AES.MODE_EAX)
        nonce = cipher.nonce
        # ----- END AES object init section -----


        # plain text
        data = connection.recv(1024) # Get data stream, not greater than 1024 bytes
        if not data: # If data is not received
            break
        print("Server recivied (plaintext): " + str(data.decode()))  # Print client data


        # Encrypt text and send it to client
        ciphertext, tag = cipher.encrypt_and_digest(data)
        print("Encrypted text: " , ciphertext)
        connection.send(pickle.dumps((nonce, ciphertext, tag)))  # Send message to the client

        
    connection.close()  # Close the connection
    print("--------------------------------------------------")
    print("Connection with " + str(address) + " is close")
    print("--------------------------------------------------")


if __name__ == '__main__':
    server_program()