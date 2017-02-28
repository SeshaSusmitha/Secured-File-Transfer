import socket
import sys
import utils
import encrypt

DATA_TRANSFER_SIZE = 1024

DEFAULT_PRIME = 197221152031991558322935568090317202983
DEFAULT_GENERATOR = 2

request = { "request_type": None,
            "payload": None}

# "request_type": "authentication",
# "request_type": "message_1",
# "request_type": "message_3",
# "request_type": "file_transfer_init",
# "request_type": "file_transfer",

client_db = {"username": None, "password": None,
             "pwd_digest": None, "client_Xa": None,
             "client_eke": None, "client_Na": None,
             "client_encrypted_final_nonce": None,
             "prime_num": DEFAULT_PRIME, "generator": DEFAULT_GENERATOR,
             "server_eke": None, "client_kas": None,
             "server_enc_nonce": None
             }

user_pswd_dict = {"username": None, "password": None}

message_1_payload = {"username": None, "prime_num" : None, "generator" : None,
                     "client_eke": None}

message_2_payload = {"server_eke": None, "server_encrypted_nonce" : None}

message_3_payload = {"username": None, "client_encrypted_final_nonce" : None}


file_transfer_payload = {"username": None, "filename": None  }

password = None
user_name = None


def get_prime_and_gene():
    return client_db['prime_num'], client_db['generator']

def get_user_cred():
    username = raw_input("Enter your username:")
    pwd = raw_input("Enter your password:")

    # username = 'naren'
    # pwd = 'password1'
    user_pswd_dict['username'] = username
    user_pswd_dict['password'] = pwd

    client_db['username'] =  username
    client_db['password'] =  pwd
    client_db['pwd_digest'] =  encrypt.generate_hash_digest(pwd)

    return user_pswd_dict

def client_send_message_1(sd):
    utils.print_trancsation_message("Client sending message 1")

    # Fetching values of generator and prime number

    p,g = get_prime_and_gene()

    # client_Xa = int(raw_input("Please enter Xa value:"))
    client_Xa = 17
    client_db['client_Xa'] = client_Xa


    client_eke = encrypt.get_eke(client_db['pwd_digest'],
                                            client_Xa,g,p)

    client_db['client_eke'] = client_eke
    #  Loading message payload

    message_1_payload['username'] = client_db['username']
    print "client_db['pwd_digest']", client_db['pwd_digest']
    message_1_payload['client_eke'] = client_eke
    message_1_payload['prime_num'] = p
    message_1_payload['generator'] = g

    request['request_type'] = 'message_1'
    request['payload'] = message_1_payload

    utils.print_dict("Payload 1",request)
    utils.print_dict("Client db",client_db)

    sd.sendall(str(request))

def client_recv_message_2(sd):
    utils.print_trancsation_message("Client receiving message 2")

    msg_2 = sd.recv(DATA_TRANSFER_SIZE)

    message_2_payload = utils.get_dict_from_string(msg_2)
    utils.print_dict("Payload 2", message_2_payload)

    client_db['server_eke'] = message_2_payload['server_eke']
    client_db['server_enc_nonce'] = message_2_payload['server_encrypted_nonce']
    utils.print_dict("Client db",client_db)

def client_send_message_3(sd):
    utils.print_trancsation_message("Client sending message 3")


    message_3_payload['username'] = client_db['username']

    server_dhkey = encrypt.decrypt_eke( client_db['server_eke'],
                                        client_db['pwd_digest'])

    client_kas = encrypt.generate_kas(server_dhkey,client_db['client_Xa'],
                                        client_db['prime_num'])
    client_db['client_kas'] = client_kas
    client_db['client_Na'] = encrypt.get_random_number()

    print "client_db['server_enc_nonce']", client_db['server_enc_nonce']
    c_server_nonce = encrypt.decrypt_nonce(client_kas, client_db['server_enc_nonce'])
    print "c_server_nonce:", c_server_nonce

    final_nonce_c = encrypt.concat(c_server_nonce, client_db['client_Na'])

    #  Client encypting final nonce with kas
    enc_final_nonce_c = encrypt.encrypt_nonce(client_kas, final_nonce_c)

    message_3_payload['username'] = client_db['username']
    message_3_payload['client_encrypted_final_nonce'] = enc_final_nonce_c
    client_db['client_encrypted_final_nonce'] = enc_final_nonce_c

    request['request_type'] = 'message_3'
    request['payload'] = message_3_payload

    utils.print_dict("Payload 3",request)
    sd.sendall(str(request))

    utils.print_dict("Client db",client_db)
    utils.print_trancsation_message("With this send Server will know if the user is valid or not")

def client_recv_message_4(sd):
    utils.print_trancsation_message("Client receiving message 4")

    msg_4 = sd.recv(DATA_TRANSFER_SIZE)

    message_4_payload = utils.get_dict_from_string(msg_4)
    utils.print_dict("Payload 4", message_4_payload)

    client_db[''] = message_4_payload['server_encrypted_Na']
    utils.print_dict("Client db",client_db)
    return message_4_payload['success']



def get_authenticated(sd):
    user_creds = get_user_cred()
    utils.print_dict("User Credentials",user_creds)

    client_send_message_1(sd)
    client_recv_message_2(sd)
    client_send_message_3(sd)
    success = client_recv_message_4(sd)
    return success

def create_socket_connection(host="localhost", port="9090"):
    port = int(port)

    sd = socket.socket()
    sd.connect((host,port))

    return sd

def file_transfer_init(socket_descriptor, filename):

    file_transfer_payload['filename'] = filename
    file_transfer_payload['username'] = client_db['username']

    request['request_type'] = "file_transfer_init"
    request['payload'] = file_transfer_payload
    utils.print_dict("File Init request",request)

    socket_descriptor.sendall(str(request))
    data = socket_descriptor.recv(DATA_TRANSFER_SIZE)

    response = utils.get_dict_from_string(data)
    utils.print_dict("File Init response",response)

    if response['file_exists'] :
        filesize = response['file_size']
        message = raw_input("File Exists, " + str(filesize)+\
                    "Bytes, download? (Y/N)? -> ")
        if message.lower() == 'Y'.lower():
            # socket_descriptor.send('OK')
            file_transfer(socket_descriptor, filename, int(filesize))
        else:
            print "File download canceled"
    else:
        print "File doesn't exist"

def file_transfer(socket_descriptor, filename, filesize):

    file_transfer_payload['filename'] = filename
    file_transfer_payload['username'] = client_db['username']

    request['request_type'] = "file_transfer"
    request['payload'] = file_transfer_payload
    utils.print_dict("File Transfer Request",request)
    socket_descriptor.sendall(str(request))
    new_filename = 'new_' +  filename

    with open(new_filename, 'wb') as f:
        print "new_filename ", new_filename
        data = socket_descriptor.recv(DATA_TRANSFER_SIZE)
        totalRecv = len(data)
        f.write(data)
        print "{0:.2f}".format((totalRecv/float(filesize))*100)+ "% Done"
        print "Naren Total recv {}, file size {}".format(totalRecv, filesize)
        while totalRecv < filesize:
            print "before recv "
            data = socket_descriptor.recv(DATA_TRANSFER_SIZE)
            totalRecv += len(data)
            f.write(data)
            print "{0:.2f}".format((totalRecv/float(filesize))*100)+ "% Done"
            print "Total recv {}, file size {}".format(totalRecv, filesize)
    print "out of while loop"

    return

def main():
    host = sys.argv[1]
    port = sys.argv[2]
    #client_Xa = sys.argv[3]

    if len(sys.argv) != 3:
        print 'Usage: python %s <HostName> <PortNumber>' % (sys.argv[0])
        sys.exit();

    sd = create_socket_connection(host, port)

    authorized = get_authenticated(sd)
    if authorized:
        print "yahooo"
    else:
        print "Boo!"

    i = 1
    while not authorized  and i <= 3:
        authorized = get_authenticated(sd)
        i+=1
        if authorized:
            print "yahooo"
        else:
            print "Boo!"


    if authorized == False and i >=3:
        sd.close()

    filename = raw_input("Filename?")

    if filename != 'q':
        file_transfer_init(sd,filename)

    print "back to main"

    sd.close()



if __name__ == '__main__':
    main()
