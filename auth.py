import db_utils as db
from collections import defaultdict
import encrypt

RETRY_MAX = 3
retry_count_dict = defaultdict(int)

auth_response = {"success": False, "max_retries":RETRY_MAX,
                    "retry_count": None, "username": None,
                    "message": None}

def authenticate(user_name, password):
    retry_count_dict[user_name] += 1
    auth_response['username'] = user_name

    if retry_count_dict[user_name] > RETRY_MAX :
        auth_response['success'] = False
        auth_response['message'] = "Reached Max retries {}".format(RETRY_MAX)
        return auth_response

    row = db.get_user_tuple(user_name)

    if encrypt.generate_hash_digest(password) == row[1]:
        auth_response['success'] = True
        auth_response['message'] = "Authrorized"
    else:
        auth_response['success'] = False
        auth_response['message'] = "Not Authrorized, retires left {}".format(
                                    RETRY_MAX - retry_count_dict[user_name])

    auth_response['retry_count'] = retry_count_dict[user_name]
    return auth_response

def get_password_for_user(user_name):
    row = db.get_user_tuple (user_name)
    return row[1]


def main():
    user_name = "naren"
    correct_pswd = "password1"

    wrng_pswd = "dummy"

    response = authenticate(user_name, wrng_pswd)
    print response

    while (int(response['max_retries']) > int(response['retry_count'])):
        print
        pwd = wrng_pswd
        if int(response['retry_count']) == 2:
             pwd = correct_pswd
        response = authenticate(user_name, pwd)
        print response

    # print is_authorized_user(user_name)
    # print is_authorized_user("user_name")

    get_password_for_user(user_name)

if __name__ == '__main__':
    main()
