import socket
import threading
import os
import sys
import auth
import utils
from collections import defaultdict
import encrypt

DATA_TRANSFER_SIZE = 1024

authorized_users = defaultdict(bool)

def is_authorized_user(user_name):
    print "authorized_users[{}] - {}".format(user_name, authorized_users[user_name])
    return authorized_users[user_name]

message_2_payload = {"server_eke": None, "server_encrypted_nonce" : None}
message_4_payload = {"server_encrypted_Na" : None, "success": False}

def transfer_file(name,file_name, sock):
    with open(file_name, 'rb') as f:
        bytesToSend = f.read(DATA_TRANSFER_SIZE)
        sock.send(bytesToSend)
        while bytesToSend != "":
            bytesToSend = f.read(DATA_TRANSFER_SIZE)
            sock.send(bytesToSend)


def get_sever_secret_key():
    # return int(raw_input("Enter your secret key: "))
    return 113

def process_message_3(payload, server_kas,server_Ns, connection):
    utils.print_trancsation_message("Server processing message 3")
    utils.print_dict("Message 3 request: ", payload)

    ser_final_nonce = encrypt.decrypt_nonce(server_kas, payload['client_encrypted_final_nonce'])

    ser_dec_ns = encrypt.get_ns_from_final_nonce(ser_final_nonce)
    ser_side_na = encrypt.get_na_from_final_nonce(ser_final_nonce)

    print "payload['client_encrypted_final_nonce']: ",  payload['client_encrypted_final_nonce']
    print "ser_final_nonce: ", ser_final_nonce
    print "ser_dec_ns : ", ser_dec_ns
    print "server_Ns  : ", server_Ns
    print "ser_side_na: ", ser_side_na

    try:
        i_ser_dec_ns = int(ser_dec_ns)
    except:
        print "sfasf"
        message_4_payload['success'] = False
        message_4_payload['server_encrypted_Na'] = "naren"
        connection.sendall(str(message_4_payload))
        return

    if (server_Ns == i_ser_dec_ns)  :
        print "Client successfully authenticated to server"
        utils.print_line()
        authorized_users[payload['username']] = True
        message_4_payload['success'] = True
    else:
        print "Hack Alert"
        message_4_payload['success'] = False
        message_4_payload['server_encrypted_Na'] = "naren"
        connection.sendall(str(message_4_payload))
        return

    #  Server sending message 4
    utils.print_trancsation_message("Server sending message 4")

    server_enc_na = encrypt.encrypt_nonce(server_kas, ser_side_na)

    print "server_enc_na: ", server_enc_na

    message_4_payload['server_encrypted_Na'] = server_enc_na
    connection.sendall(str(message_4_payload))
    utils.print_dict("message_4_payload", message_4_payload)
    # Server sending message 5
    utils.print_trancsation_message("Server sending message 4")




def process_message_1(payload, server_nonce, connection):
    utils.print_trancsation_message("Server processing message 1")
    utils.print_dict("process_secret_key_request",payload)

    # Getting password digest for user name
    pass_digest = auth.get_password_for_user(payload['username'])
    print "\n"
    print "pass_digest: ",pass_digest

    # Get client dh key from client EKE
    client_dhkey = encrypt.decrypt_eke(payload['client_eke'], pass_digest)
    print "\n"
    print "client_dhkey: ",client_dhkey

    server_Xa = get_sever_secret_key()

    # Generate server dh key
    server_dhkey = encrypt.generate_dh_key( server_Xa,
                                            int(payload['generator']),
                                            int(payload['prime_num']) )
    print "server_dhkey: ",server_dhkey

    # Generate server EKE
    server_eke = encrypt.generate_EKE(server_dhkey, pass_digest)
    print "\n"
    print "server_eke: ",server_eke

    # Generate server KAS
    server_kas = encrypt.generate_kas(  client_dhkey,
                                        server_Xa,
                                        payload['prime_num'] )
    print "\n"
    print "server_kas: ",server_kas


    print "\n"
    print "server nonce: ", server_nonce

    # message_2_payload = {"server_eke": None, "server_encrypted_nonce" : None}
    # Encrypt Nonce using KAS
    encrypted_server_nonce = encrypt.encrypt_nonce(int(server_kas), (server_nonce))
    print "encrypted_nonce: ", encrypted_server_nonce

    # Send Server EKE and Encrypted Nonce to client
    message_2_payload = {"server_eke" : server_eke, "server_encrypted_nonce": encrypted_server_nonce}
    utils.print_dict( "Server EKE and Encrypted Nonce", message_2_payload)

    connection.sendall(str(message_2_payload))

    return int(server_kas)


def process_file_transfer_init_request(payload, connection):
    print "process_file_transfer_init_request - payload ", payload

    if not is_authorized_user(payload['username']):
        print "Hack attempt"
        return False

    file_name = payload['filename']

    response = {"file_name": file_name,
                "file_exists": None,
                "file_size": None}

    if os.path.isfile(file_name):
        response["file_exists"] = True
        response["file_size"] = str(os.path.getsize(file_name))
    else:
        response["file_exists"] = False
        response["file_size"] = ""

    return response

# File Transfer
def process_file_transfer_request(payload, connection):

    if not is_authorized_user(payload['username']):
        print "Hack attempt"
        return False

    file_name = payload['filename']
    t = threading.Thread(target=transfer_file, args=("FileTransferThread",
                                                        file_name,
                                                        connection))
    t.start()
    return True


def main():
    #host = '127.0.0.1'
    #port = 7070

    # Taking host name and port number from command line
    host = sys.argv[1]
    port = sys.argv[2]

    port = int(port)

    if len(sys.argv) != 3:
        print 'Usage: python %s <HostName> <PortNumber>' % (sys.argv[0])
        sys.exit();

    # Socket creation,binding it a address and listening for client conenction
    sd = socket.socket()
    sd.bind((host,port))

    sd.listen(5)
    retry_count = 0;
    print "\n"
    print "Socket created and server is running"
    print "\n"

    # Accepting a connection from client
    c, addr = sd.accept()
    print "Client connected ip:<" +str(port) + ">"
    request = None
    while True:

        print "Entering loop"
        try:
            request = utils.get_dict_from_string(
                                            c.recv(DATA_TRANSFER_SIZE))
            # utils.print_dict( "Request from client", request)
            if request is None or request == "":
                print "Data received None"
                break
        except Exception as e:
            break


        if request  != "" :
            if request['request_type'] == "message_1":
                # Get server nonce
                server_Ns = encrypt.get_random_number()
                s_kas = process_message_1(request['payload'], server_Ns,c)

            if request['request_type'] == "message_3":
                process_message_3(request['payload'],s_kas,server_Ns, c)

            if request['request_type'] == "file_transfer_init":
                response = process_file_transfer_init_request(request['payload'], c)
                utils.print_dict("File transfer init request from client", response)
                c.sendall(str(response))

            if request['request_type'] == "file_transfer":
                process_file_transfer_request(request['payload'], c)


    sd.close()

if __name__ == '__main__':
    main()
