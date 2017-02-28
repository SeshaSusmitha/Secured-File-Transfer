import math
import hashlib

# SHA1 digest for password
def generate_SHA1(password):
    hash_object = hashlib.sha1(password)
    pwd_digest = hash_object.hexdigest()
    return pwd_digest

# Diffi hellman key generation
def generate_dh_key(secret_key,
                    generator = 2,
                    prime_num = 197221152031991558322935568090317202983
                    ):
    dh_key = pow(generator,secret_key,prime_num)
    return dh_key

# Encrypion of Diffi Hellman key using password
def generate_EKE(dh_key, pwd_digest):
    pwd_dig_decimal = int(pwd_digest,16)
    enc_dhkey = dh_key ^ pwd_dig_decimal
    return enc_dhkey

def decrypt_eke(enc_dhkey,pwd_digest):
    dec_eke = enc_dhkey ^ int(pwd_digest,16)
    return dec_eke

# print "math.pow({}, {}) = {}, len(gpowerx ):{} ".format(g, xa, gpowerx,

def main():
    secret_key = long(raw_input("Enter your Xa:"))
    # generator = 3
    # prime_num = 197221152031991558322935568090317202983
    password  = "password"
    dh_key = generate_dh_key( secret_key)
    # dh_key = generate_dh_key( secret_key, 3, 7)
    pwd_digest = generate_SHA1(password)
    eke = generate_EKE(dh_key, pwd_digest)
    print "eke: ",eke
    print "pwd_digest: ",pwd_digest
    print "decrypt: ",decrypt_eke(eke,pwd_digest)
    print "dh_key: ", dh_key



if __name__ == '__main__':
    main()
