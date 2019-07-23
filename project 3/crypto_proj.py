import hashlib
import json
import math
import os
import random
# You may NOT alter the import list!!!!


class CryptoProject(object):

    def __init__(self):
        # TODO: Change this to YOUR Georgia Tech student ID!!!
        # Note that this is NOT your 9-digit Georgia Tech ID
        # self.student_id = 'bdornier3'  # for test_crypto_proj_1.py
        # self.student_id = 'ctaylor'  # for test_crypto_proj_2.py
        self.student_id = 'rpatel475'

    def get_student_id_hash(self):
        return hashlib.sha224(self.student_id.encode('UTF-8')).hexdigest()

    def get_all_data_from_json(self, filename):
        data = None
        base_dir = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(base_dir, filename), 'r') as f:
            data = json.load(f)
        return data

    def get_data_from_json_for_student(self, filename):
        data = self.get_all_data_from_json(filename)
        name = self.get_student_id_hash()
        if name not in data:
            print(self.student_id + ' not in file ' + filename)
            return None
        else:
            return data[name]

    # TODO: OPTIONAL - Add helper functions below
    # NOTES
    ## public key (e, N)
    ## private key (d)
    ## N = p * q where p, q are distinst prime numbers
    ## e such that 1 < e < phiN and gcd(e, phiN) = 1 where phiN = (p-1)*(q-1)
    ## 
    ## enc m with (N, e) = c
    ### c = m^e % M
    ## dec c with d into m
    ### m = c^d % N

    # BEGIN HELPER FUNCTIONS
    # muliplicative modular inverse
    def modInverse(self, a, m):
        gcd, x, y = self.exgcd(a, m)
        if gcd != 1:
            raise Exception('No modular inverse')
        return x % m

    # gcd with extended euclidean algorithm
    def exgcd(self, a, b):
        if a == 0:
            return b, 0, 1
        gcd, y, x = self.exgcd(b%a, a)
        return gcd, x - (b//a) * y, y

    # chinese remainder theorem
    def crt(self, n, r):
        k = len(n)
        prod = 1
        for i in range(k):
            prod *= n[i]
        res = 0
        for i in range(k):
            p = prod // n[i]
            res = res + r[i] * self.modInverse(p, n[i]) * p
        return res % prod

    # find cube root of large number
    def cbrt(self, x):
        lo = 1
        hi = x
        mid = (hi + lo)//2
        while lo <= hi:
            #  print("hi: " + str(hi) + " , mid: " + str(mid) + " , lo: " + str(lo))
            c = mid*mid*mid
            if c == x:
                return mid
            elif c > x:
                hi = mid - 1
            elif c < x:
                lo = mid + 1
            mid = (hi + lo)//2

        return 0
            
    # END HELPER FUNCTIONS

    def decrypt_message(self, N, e, d, c):
        # TODO: Implement this function for Task 1
        # m = 0
        m = pow(c, d, N)
        return hex(m).rstrip('L')

    def crack_password_hash(self, password_hash, weak_password_list):
        # TODO: Implement this function for Task 2
        # password = 'abc'
        # salt = '123'
        for password in weak_password_list:
            for salt in weak_password_list:
                hashed_password = hashlib.sha256(password.encode() + salt.encode()).hexdigest()
                if password_hash == hashed_password:
                    return password, salt
        #return password, salt

    def get_factors(self, n):
        # TODO: Implement this function for Task 3
        p = 0
        q = 0
        sq = math.floor(math.sqrt(n))
        if sq % 2 == 0:
            sq -= 1
        for i in range(sq, n, 2):
            if n % i == 0:
                q = int(i)
                p = int(n/q)
                break
        return p, q

    def get_private_key_from_p_q_e(self, p, q, e):
        # TODO: Implement this function for Task 3
        phiN = (p-1) * (q-1)
        # d = 0
        d = self.modInverse(e, phiN)
        return d
        

    def is_waldo(self, n1, n2):
        # n1 is my key, n2 is classmate's key
        # using keys4student_task_4.json, determine whether n2 belongs to Waldo
        # TODO: Implement this function for Task 4
        # look for common gcd between n1 and n2
        # if gcd is not one then you have a common p or q
        # result = False
        gcd, x, y = self.exgcd(n1, n2)
        return gcd != 1

    def get_private_key_from_n1_n2_e(self, n1, n2, e):
        # now that we found Waldo, generate private key using n1 (own key), n2 (Waldo's public key)
        # TODO: Implement this function for Task 4
        # find gcd between n1 and n2, this gives p
        # divide n1/p to get q
        p, x, y = self.exgcd(n1, n2)
        q = n1//p
        phiN = (p - 1) * (q - 1)
        #d = 0
        d = self.modInverse(e, phiN)

        return d

    def recover_msg(self, N1, N2, N3, C1, C2, C3):
        # e = 3
        # given 3 pairs of public keys and their encrypted message (Nn, Cn)
        ## return the origina message
        ### all keys and messages can be found in keys4student_task_5.json
        # TODO: Implement this function for Task 5
        #  Chinese Remainder
        n = [N1, N2, N3]
        r = [C1, C2, C3]
        rem = self.crt(n, r)
        m = self.cbrt(rem)
        return m

    def task_1(self):
        data = self.get_data_from_json_for_student('keys4student_task_1.json')
        N = int(data['N'], 16)
        e = int(data['e'], 16)
        d = int(data['d'], 16)
        c = int(data['c'], 16)

        m = self.decrypt_message(N, e, d, c)
        return m

    def task_2(self):
        data = self.get_data_from_json_for_student('hashes4student_task_2.json')
        password_hash = data['password_hash']

        # The password file is loaded as a convenience
        weak_password_list = []
        base_dir = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(base_dir, 'top_passwords.txt'), 'r', encoding='UTF-8-SIG') as f:
            pw = f.readline()
            while pw:
                weak_password_list.append(pw.strip('\n'))
                pw = f.readline()

        password, salt = self.crack_password_hash(password_hash, weak_password_list)

        return password, salt

    def task_3(self):
        data = self.get_data_from_json_for_student('keys4student_task_3.json')
        n = int(data['N'], 16)
        e = int(data['e'], 16)

        p, q = self.get_factors(n)
        d = self.get_private_key_from_p_q_e(p, q, e)

        return hex(d).rstrip('L')

    def task_4(self):
        all_data = self.get_all_data_from_json('keys4student_task_4.json')
        student_data = self.get_data_from_json_for_student('keys4student_task_4.json')
        n1 = int(student_data['N'], 16)
        e = int(student_data['e'], 16)

        d = 0
        waldo = 'Dolores'

        for classmate in all_data:
            if classmate == self.get_student_id_hash():
                continue
            n2 = int(all_data[classmate]['N'], 16)

            if self.is_waldo(n1, n2):
                waldo = classmate
                d = self.get_private_key_from_n1_n2_e(n1, n2, e)
                break

        return hex(d).rstrip("L"), waldo

    def task_5(self):
        data = self.get_data_from_json_for_student('keys4student_task_5.json')
        N1 = int(data['N0'], 16)
        N2 = int(data['N1'], 16)
        N3 = int(data['N2'], 16)
        C1 = int(data['C0'], 16)
        C2 = int(data['C1'], 16)
        C3 = int(data['C2'], 16)

        m = self.recover_msg(N1, N2, N3, C1, C2, C3)
        # Convert the int to a message string
        msg = bytes.fromhex(hex(m).rstrip('L')[2:]).decode('UTF-8')

        return msg
