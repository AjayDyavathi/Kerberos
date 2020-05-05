# Implementation of Kerberos protocol
# Author: Ajay Dyavathi
# 
# Description: Kerberos is a computer-network authentication protocol that works on the basis of tickets to allow end systems 
# to communicate over an unsecured channel using symmertric key encryption where each end system has a single shared key with 
# authentication server, which authenticates user and provides further communication with ticket granting server, which
# grants a common ticket for two end systems to communicate with symmetric key encryption.


import datetime, random

class xor_cipher():
    ''' Very simple stream cipher '''

    def __init__(self):
        ''' Basic stream cipher on ascii string and ascii key'''
        pass

    def ascii2bin(self, string):
        ''' Converts ascii string to binary bitstring '''

        return ''.join('{:08b}'.format(ord(asc)) for asc in string)

    def bin2ascii(self, binary):
        ''' Converts binary bitstring to ascii string '''

        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

    def bin2hex(self, bn):
        ''' Converts binary bitstring to hex string '''

        return ''.join('{:x}'.format(int(bn[i:i+4], 2)) for i in range(0, len(bn), 4))

    def hex2bin(self, hx):
        ''' Converts hex string to binary bitstring '''

        return ''.join('{:04b}'.format(int(h, 16)) for h in hx)

    def xor(self, a, b):
        ''' Performs XOR operation of given two inputs a, b '''

        return ''.join('0' if i == j else '1' for i, j in zip(a, b))

    def encrypt(self, message, key):
        ''' Performs encryption on message with key, this is xor operation between message and expanded key '''

        # expanding key to the length of message
        key += key*(len(message)-len(key))
        # converting ascii strings to binary to perform XOR
        message, key = self.ascii2bin(message), self.ascii2bin(key)
        # performing xor operation
        encrypted = self.xor(message, key)
        # converting binary to hex string as cipher
        return self.bin2hex(encrypted)

    def decrypt(self, message, key):
        ''' Performs decryption on message with key, this is xor operation between message and expanded key '''

        # expanding key to the length of message
        key += key*(len(message)-len(key))
        # converting hex message and ascii key to binary
        message, key = self.hex2bin(message), self.ascii2bin(key)
        # performing xor operation
        decrypted = self.xor(message, key)
        # converting binary to ascii as plain text
        return self.bin2ascii(decrypted)


class user():
    '''USER class'''

    def __init__(self, name, authenticate_shared_key, database, nonce):
        ''' User is one participant in the network, 
            (name, authentication server shared key, database to communicate with, nonce) '''

        self.name = name
        self.auth_key = authenticate_shared_key
        self.database = database
        self.nonce = nonce

    def prepare_auth_request(self):
        ''' Prepares request for authentication server '''

        # returns a tuple with (name, database name, nonce)
        return (self.name, self.database, self.nonce)

    def process_auth_response(self, cipher1, cipher2):
        ''' Process the response from authentication server '''

        # eval is used to extract tuple from string
        response_to_user = eval(cipher.decrypt(cipher1, self.auth_key))   
        # unpacking tuple into individual elements, OBTAINED USER-TICKET KEY (common for user and TGS)!!
        self.user_ticket_key, nonce, time, ttl, dest = response_to_user 
        # verify nonce    
        assert nonce == self.nonce  
        # verify destination name                                        
        assert dest == 'ticket_granting_server'  
        # 2nd element in response is ticket for TGS encrypted with TGS-auth key (common for TGS and auth)                           
        self.ticket_granting_ticket = cipher2                              
        return response_to_user

    def prepare_ticket_request(self):
        ''' Prepare request for TGS '''

        # request is a tuple with (name, time, database name, nonce)
        request = str((self.name, str(datetime.datetime.now().date()), self.database, self.nonce))
        # encrypt the request with user-ticket key (common for user and TGS)
        encrypted_request = cipher.encrypt(request, self.user_ticket_key)
        return (encrypted_request, self.ticket_granting_ticket)

    def process_ticket_response(self, cipher1, cipher2):
        ''' Process the response from TGS '''

        # extracting tuple from string
        response_to_user = eval(cipher.decrypt(cipher1, self.user_ticket_key))
        # unpacking elements into individual elements, "USER-DATABASE" key is obtained!! common for USER and DATABASE
        self.user_database_key, nonce, time, life, destination = response_to_user
        # 2nd response from TGS is a ticket for database encrypted with database-TGS key (common for database and TGS)
        self.database_ticket = cipher2
        # verify nonce
        assert self.nonce == nonce
        # verify database name
        assert self.database == destination
        # if everything is verified, which indicates user is authenticated, then create an object for database
        # in practice, no such thing happens, because a physical database will be available
        if self.database == destination:
            num_db = dataserver()
        # return the created object, which in practice returning the permission to access database
        return num_db

    def prepare_database_request(self):
        ''' Prepares a request for database '''

        # create a random token, later used for acknowledgement purpose
        self.token = random.randint(1, 100)
        # create a request tuple with (name, token) for database
        request = str((self.name, self.token))
        # encrypt the request with user-database key, common for USER and DATABASE
        encrypted_request = cipher.encrypt(request, self.user_database_key)
        return (encrypted_request, self.database_ticket)

    def process_database_response(self, response):
        ''' Process the database response'''

        # verify is token is incremented by 1, which is ACKNOWLEDGEMENT
        assert self.token+1 == response

    def prepare_database_data_request(self, database, request):
        ''' Prepare data access requests for database'''

        # data access requests and responses are encrypted with share (user-database) key
        return cipher.encrypt(f'{database}.get_data({request})', self.user_database_key)


class authentication_server():
    '''AUTHENTICATION SERVER class'''

    def __init__(self):
        '''  Authentication Server, as a part of Key Disrtibution Centre (KDC), which authenticates users '''

        # Authentication server should have the list of all shared passwords between users and Auth server
        # TGS keys are inbuilt, as new users get added, their keys will be updated with set_key method
        self.keys = {'tgs': 'tgs123'}

    def set_key(self, name, key):
        ''' Sets new key for new users into network'''

        self.keys[name] = key

    def get_key(self, name):
        ''' Returns the user's key '''

        return self.keys[name]

    def process_request_respond(self, request):
        ''' Process the user request and respond '''

        # unpack user request tuple into individual elements
        self.client_name, self.destination, self.nonce = request
        # return 2 encrypted responses, one for user (encrypted with user-auth key), another for TGS (encrypted with tgs_auth key) 
        return (self.response_for_user(), self.response_for_TGS())

    def response_for_user(self):
        ''' Prepare a response for user '''

        # create a random new key as a common key for USER and TGS
        self.user_ticket_key = str(random.randint(1, 100))
        # create a response tuple with (user-ticket key, nonce, time, span, TGS name)
        response = (self.user_ticket_key, self.nonce, str(datetime.datetime.now().date()), '3 days', 'ticket_granting_server')
        # since, this is response for user, it is encrypted with common key of auth-server and user
        return cipher.encrypt(str(response), self.keys[self.client_name])

    def response_for_TGS(self):
        ''' Prepare a response for TGS '''

        # create a response tuple with (user-ticket key, client name, span)
        response = (self.user_ticket_key, self.client_name, '3 days')
        # since, this response is for TGS, it is encrypted with common key of auth-server and TGS
        return cipher.encrypt(str(response), self.keys['tgs'])


class ticket_granting_server():
    '''TICKET GRANTING SERVER class'''
    def __init__(self):
        ''' Ticket Granting Server (TGS), as a part of Key Distribution Centre (KDC), which creates session keys between users'''

        # personal key for TGS to communicate with Authentication Server
        self.personal_key = 'tgs123'
        # database keys at TGS
        self.keys = {'number_database': 'alpha'}
    
    def process_auth_user_request_respond(self, user_request, auth_response):
        ''' Process user_request and auth_response_for_TGS and respond'''

        # decrypt and exrtact the tuple with personal key, as this is encrypted by auth server
        auth_response = eval(cipher.decrypt(auth_response, self.personal_key))
        # unpack auth response into individual elements, obtained USER-TICKET key (common for user and TGS)
        self.user_ticket_key, client_name, life = auth_response

        # decrypt and extract user request with USER-TICKET key obtained in above auth response
        user_request = eval(cipher.decrypt(user_request, self.user_ticket_key))
        # unpack user request into individual elements
        self.user_name, time, self.destination, self.nonce = user_request
        # return two encrypted responses, one for user (encrypted with user-tgs key), another for database (with database-tgs key)
        return (self.response_for_user(), self.response_for_database())

    def response_for_user(self):
        ''' Prepare a response for USER '''

        # create a key common key for USER - DATABASE
        self.user_database_key = str(random.randint(1, 100))
        # create response data tuple with (user-database key, nonce, time, span, database name)
        response = str((self.user_database_key, self.nonce, str(datetime.datetime.now().date()), '5 days', self.destination))
        # encrypt the response with USER-TGS key, common for user and TGS.
        return cipher.encrypt(response, self.user_ticket_key)


    def response_for_database(self):
        ''' Prepare a response for DATABASE '''

        # create a response tuple with (user-database key, user name, span)
        response = str((self.user_database_key, self.user_name, '5 days'))
        # encrypt response with DATABASE-TGS key, common for TGS and Database
        return cipher.encrypt(response, self.keys[self.destination])


class dataserver():
    ''' DATASERVER class '''
    def __init__(self):
        ''' This can be another participant or a data server in a network '''

        # this personal key is pre-shared with TGS  
        self.personal_key = 'alpha'
        # example data in database
        self.data = {1: 'One', 2: 'Two', 3: 'Three'}

    def __str__(self):
        return 'number_database'

    def get_data(self, index):
        ''' Get the data from database '''

        # verify if request is valid
        assert index in self.data.keys()
        # return data
        return self.data[index]

    def process_client_request_respond(self, client_token, db_ticket):
        ''' Process client request and respond '''

        # process db ticket
        # db_ticket is dedicated for database, which can be decrypted with database's personal key 
        db_ticket = eval(cipher.decrypt(db_ticket, self.personal_key))
        # unpack into individual elements, obtained USER-DATABASE key !!
        self.user_database_key, user_name, life = db_ticket

        # process client token
        # decrypt client token with user-database key obtained in above ticket
        client_token = eval(cipher.decrypt(client_token, self.user_database_key))
        # unpack token into individual elements
        self.client_name, self.token = client_token
        # verify name
        assert self.client_name == user_name
        # if name is valid, then acknowledge user by incrementing token by 1
        return self.token + 1

    def process_data_request_respond(self, request):
        '''Process data request and respond '''

        # decrypt the user request with user-database key and evaluate the request
        return eval(cipher.decrypt(request, self.user_database_key))


# setup ciphering function
cipher = xor_cipher()

# setup database server
# this is created as a string, to verify across the process
# database object is created when requesting user is authenticated in later steps
db = 'number_database'

# setup user
username = 'ajay'
userkey = 'secret_key'
user1 = user(username, userkey, db, 12)

# setup authentication server
auth_server = authentication_server()
# add user with key in authentication server
auth_server.set_key(username, userkey)

# setup ticket granting server
ticket_server = ticket_granting_server()

# KERBEROS PROTOCOL

# prepare auth request -> send to auth server -> auth authenticates and responds -> process the auth response
user_request_to_auth = user1.prepare_auth_request()
response_to_user_from_auth, response_to_tgs_from_auth = auth_server.process_request_respond(user_request_to_auth)
auth_response_to_user = user1.process_auth_response(response_to_user_from_auth, response_to_tgs_from_auth)

# prepare tgs request -> send to tgs -> tgs process tickets and responds -> process the tgs response
user_request_to_tgs, ticket_request_from_auth = user1.prepare_ticket_request()
response_to_user_from_tgs, response_to_db_from_tgs = ticket_server.process_auth_user_request_respond(user_request_to_tgs, ticket_request_from_auth)
database1 = user1.process_ticket_response(response_to_user_from_tgs, response_to_db_from_tgs)

# prepare database request -> send to database -> database acknowledges and responds -> process the response
user_request_to_db, db_ticket_from_tgs = user1.prepare_database_request()
database_response = database1.process_client_request_respond(user_request_to_db, db_ticket_from_tgs)
user1.process_database_response(database_response)

# verify user and database successfully shared common keys
assert user1.user_database_key == database1.user_database_key
print('Key Establishment successful..!')

# request data from database
request_data = 1
request = user1.prepare_database_data_request('database1', request_data)
response = database1.process_data_request_respond(request)
# enjoy response
print(request_data, response)
