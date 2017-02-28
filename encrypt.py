import math
import hashlib
import md5
from Crypto import Random
from Crypto.Cipher import AES
import base64
import bbs
import random
import uuid
import utils

DEFAULT_PRIME = 197221152031991558322935568090317202983
DEFAULT_GENERATOR = 2

# BS = 16
# pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
# unpad = lambda s : s[:-ord(s[len(s)-1:])]

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]
def get_random_number():
    return bbs.blum_blum_shub()

    #return random.randint(11111111111111111,999999999999999999)


def generate_hash_digest(password):
    return generate_SHA1(password)

# SHA1 digest for password
def generate_SHA1(password):
    hash_object = hashlib.sha1(password)
    pwd_digest = hash_object.hexdigest()
    return pwd_digest
    # print "password is: ",password
    # salt = uuid.uuid4().hex
    # print "salt is: ",salt
    # pwd_digest = hashlib.sha512(password + salt).hexdigest()
    # print "pwd digest: ",pwd_digest
    # return pwd_digest

# Diffi hellman key generation
def generate_dh_key(secret_key,
                    generator ,
                    prime_num
                    ):
    dh_key = pow(generator,secret_key,prime_num)
    return dh_key

# Encrypion of Diffi Hellman key using password
def generate_EKE(dh_key, pwd_digest):
    return xor(dh_key , int(pwd_digest,16))

def decrypt_eke(enc_dhkey,pwd_digest):
    return xor(enc_dhkey , int(pwd_digest,16))

def get_eke(pwd_digest, secret_key,
            generator ,
            prime_num ):
    dh_key = generate_dh_key(secret_key,generator,prime_num)
    enc_dhkey = generate_EKE(dh_key,pwd_digest)
    return enc_dhkey

def generate_kas(dh_key, secret_key, prime_num ):
    kas = pow(dh_key,secret_key,prime_num)
    return kas

def xor(val1, val2):
    return val1 ^ val2
    # val3 = int(val1 ,2) ^ int(val2, 2)
    # return val3

def concat(val1, val2):
    return str(val1) + str(val2)

def get_ns_from_final_nonce(final_nonce):
    return final_nonce[:len(final_nonce)/2]

def get_na_from_final_nonce(final_nonce):
    return final_nonce[len(final_nonce)/2:]

def encrypt_kas(kas, random_number):
    return xor(kas , random_number)

def encrypt_nonce(kas, random_number):
    if isinstance(kas,int) and isinstance(nonce,int):
        return -1
    return aes_cbc_encrypt( kas, random_number )

def decrypt_nonce(kas, encrypted_random_number):
    return aes_cbc_decrypt( kas, encrypted_random_number )

def encrypt_client_and_server_nonce(s_nonce, c_nonce):
    print "s_nonce({}) -> {} \nc_nonce({}) -> {}".format(type(s_nonce), s_nonce,
                                                    type(c_nonce), c_nonce)
    return xor(s_nonce, c_nonce)

def aes_cbc_encrypt( kas, message ):
    key = md5.new(str(kas)).digest()
    message = str(message)
    message = pad(message)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return base64.b64encode( iv + cipher.encrypt( message ) )

def aes_cbc_decrypt( kas, enc ):
    key = md5.new(str(kas)).digest()
    enc = base64.b64decode(enc)
    iv = enc[:BS]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[BS:] ))

def _aes_cbc_encrypt( kas, random_number ):
    key = md5.new(str(kas)).digest()
    message = str(random_number)
    message = pad(message)
    iv = Random.new().read( AES.block_size )
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return base64.b64encode( iv + cipher.encrypt( message ) )

def _aes_cbc_decrypt( kas, enc):
    key = md5.new(str(kas)).digest()
    enc = base64.b64decode(enc)
    iv = enc[:BS]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    print "aes_cbc_decrypt ", cipher
    val = unpad(cipher.decrypt( enc[BS:] ))
    print "aes_cbc_decrypt unpad ",val
    return val
# print "math.pow({}, {}) = {}, len(gpowerx ):{} ".format(g, xa, gpowerx,

def test():
    secret_key = 223
    generator = 3
    prime_num = 197221152031991558322935568090317202983
    password  = "password1"
    random_number = 197221152031991558322935568090317202983
    dh_key = generate_dh_key( secret_key, generator, prime_num)
    pwd_digest = generate_SHA1(password)
    eke = get_eke(pwd_digest,secret_key,generator,prime_num)

    print "secret_key: ", secret_key
    print "eke: ",eke
    print "pwd_digest: ",pwd_digest
    print "decrypt: ",decrypt_eke(eke,pwd_digest)
    print "dh_key: ", dh_key
    kas =  generate_kas(dh_key,secret_key,prime_num)
    print "kas: ", kas
    print "enc kas: ", encrypt_kas(kas,random_number)

    kas = 25494605730065883870637428293146839535

    client_dh_key = dh_key
    ########################
    # server encrypting nonce and sending to client """message 2"""
    utils.print_line()

    server_kas =  kas
    server_Xs = 23

    server_eke = get_eke(pwd_digest,server_Xs,generator,prime_num)

    server_Ns = get_random_number()

    server_enc_nonce = encrypt_nonce(server_kas, server_Ns)

    print "server_eke: ",server_eke

    print "server_Ns: ", server_Ns
    print "server_enc_nonce: ", server_enc_nonce


    #  Client decryptin server nonce
    client_Ns = get_random_number()
    client_kas = kas
    c_server_nonce = int(decrypt_nonce(client_kas, server_enc_nonce))

    print "client side c_server_nonce: ", c_server_nonce

    #  Client encrypting server and client nonce, creating final nonce
    final_nonce_c = concat(c_server_nonce, client_Ns)
    final_nonce_x = xor(c_server_nonce, client_Ns)

    #  client encypting final nonce with kas
    enc_final_nonce_c = encrypt_nonce(client_kas, final_nonce_c)
    enc_final_nonce_x = encrypt_nonce(client_kas, final_nonce_x)

    print "final_nonce_c: ", final_nonce_c
    print "final_nonce_x: ", final_nonce_x
    print "enc_final_nonce_c: ", enc_final_nonce_c
    print "enc_final_nonce_x: ", enc_final_nonce_x


    #  Server side decryptin mesage 3

    ser_final_nonce = decrypt_nonce(server_kas, enc_final_nonce_c)

    ser_dec_ns = get_ns_from_final_nonce(ser_final_nonce)
    ser_side_na = get_na_from_final_nonce(ser_final_nonce)

    print "ser_dec_ns : ", ser_dec_ns
    print "server_Ns  : ", server_Ns
    print "ser_side_na: ", ser_side_na

    #  Server sending message 4

    server_enc_na = encrypt_nonce(server_kas, ser_side_na)

    print "server_enc_na: ", server_enc_na

    utils.print_line()
    ########################

    print "\n# Sever sending enc server nonce to client"
    server_nonce = get_random_number()
    enc = aes_cbc_encrypt(kas, server_nonce)
    print server_nonce, "->", enc

    print "\n# Client decrypting the enc_nonce sent from server"
    client_dec_server_nonce = aes_cbc_decrypt(kas, enc)
    print "client_dec_server_nonce", client_dec_server_nonce

    print "\n# Client generating client nonce"
    client_nonce = get_random_number()

    enc = aes_cbc_encrypt(kas,client_nonce)
    print client_nonce, "->", enc

    print "\n# Client encrypting c_nonce and s_nonce"
    enc_c_s_nonce = encrypt_client_and_server_nonce( int(client_dec_server_nonce),
                                                    client_nonce)

    encrypted_nonce_wid_kas =  encrypt_nonce(kas, enc_c_s_nonce)

    print "encrypted_nonce_wid_kas", encrypted_nonce_wid_kas

    print "\n# Send encrypted_nonce_wid_kas and user name to server"

    dec = aes_cbc_decrypt(kas, enc)
    print dec






if __name__ == '__main__':
    test()
