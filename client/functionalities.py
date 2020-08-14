from OpenSSL import SSL
import os, socket
from shared.client import *
from shared.globle import *
from shared.openssl import *
import threading
import base64



class Listener(threading.Thread):
    def __init__(self, socket,output,commands):
        super().__init__()
        self.output=output
        self.socket=socket
        self.commands=commands

    def process_msg(self,msg):
        commande=msg.split(':')[0]
        if(commande not in self.commands):
            return msg
        result=self.commands[commande](msg.split(commande+':')[1])
        return None

    def run(self):
        try:
             while 1:
                 msg = self.socket.recv(buffersize).decode("utf-8")
                 msg = self.process_msg(msg)
                 if (msg != None):
                     self.output(msg)
        except Exception as e:
            print(e)
            self.socket.close()

class Clientf:
    def __init__(self,host=hostCS,port=portCS,key='keys/client.key',cert='keys/client.cert',authourity='keys/CA.cert',passphrase=''):
        # Initialize context
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, verify_cb)  # Demand a certificate
        self.key=load_key_file(key,passphrase)
        ctx.use_privatekey(self.key)
        ctx.use_certificate_file(os.path.join(cert))
        ctx.load_verify_locations(os.path.join(authourity))

        # Set up client
        self.socket = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.socket.connect((host, port))
        self.commands={newpettern:self.add_user,deletpattern:self.delete_user}
        self.clients={}
        self.selected=None
        self.sign=False

    def delete_user(self,user):
        self.deleteClient(user)

    def authentification(self,client):
        json=client.serialise()
        try:
            self.socket.send(json)
        except Exception:
            return
        auth=self.socket.recv(buffersize).decode("utf-8")
        if(auth=="TRUE"):
            return True
        else:
            return auth

    def start_listener(self,output,addClient,deleteClient):
        self.print=output
        self.addClient=addClient
        self.deleteClient=deleteClient
        listener=Listener(self.socket,self.output,self.commands)
        listener.start()

    def add_user(self,info):
        infos=info.split("||")
        cert=infos[1].encode()
        a=bytes_to_certif(cert)
        self.clients[infos[0]]=a
        self.addClient(infos[0])

    def send(self,text):
        try:
            if self.selected!=None:
                text=encrypt_with_certif(self.selected,text)
                text=cryptpattern+text+cryptpattern
            if self.sign:
                signature=sign(self.key,text)
                text=signature + signpattern + text
            self.socket.send(text)
        except Exception as e:
            print (e)
            return

    def active_sign(self):
        self.sign = not self.sign

    def select_destination(self,login):
        try:
            self.selected=self.clients[login]
        except Exception as e:
            self.selected=None
            print (e)

    def output(self,msg: str):
        text=''
        if signpattern in msg:
            m = msg.split(signpattern)
            signature = m[0]
            msg = m[1]
            for key,cert in self.clients.items():
                if(verify(cert,signature,msg)):
                    text+='<span style=\"color: yellow\">'+key+'</span>: '
                    break
        if (text == ''):
            text += '<span style=\"color: green\"> anonyme: </span>'

        if cryptpattern in msg:
            d=decrypt(self.key,msg.split(cryptpattern)[1])
            if(d==None):
                text+="<span style=\"color: red\">  crypted message </span>"
            else:
                text+=d
        else:
            text+=msg

        self.print(text)

    def __del__(self):
        try:
            self.socket.shutdown()
        except Exception as e:
            return
        try:
            self.socket.close()
        except Exception as e:
            return

        print("shutdown")






####################
class Resgistration:
    
    def __init__(self,host=hostPKI,port=portPKI):
        self.client = None
        self.host = host
        self.port = port
        self.my_socket = None

    def __del__(self):
        #self.my_socket.shutdown()
        try:
            self.my_socket.close()
        except Exception as e:
            print(e)
            return

    def fill_client_info(self,nom='',prenom='',login='',password='',num=0,certification=None):
    
        #
        self.client =  Client(num, nom, prenom, login, password, certification)
        # pour le test
        #self.client = Client(33373, 'cn3', 'sn3', 'uid3', 'pwd3', 'certif3')

    def generate_keypPair(self):
        self.key_pair = create_keyPair(crypto.TYPE_RSA, 1024)

    def fill_certification_request_info(self, C="CN", ST = "ST", L="L", O="O", OU="OU", CN="CN", emailAddress="E-mail address"):
        self.client.certification = create_certRequest(self.key_pair,C=C, ST=ST, L=L, O=O, OU=OU, CN=CN, emailAddress=emailAddress)

    def set_up_socket(self):
        if not self.my_socket:
            self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.my_socket.connect((self.host, self.port))

    def validate_with_pki(self,registration_directory,passphrase):
        # send client and certif request
        serialised_client = self.client.serialise().encode('utf-8')
        self.my_socket.send(serialised_client)
        # recieve client object with his new certifcat
        # recieve authority certifcat
        client_json_object_and_authority_certif = self.my_socket.recv(buffersize).decode("utf-8")
        if client_json_object_and_authority_certif == "error client exist":
            print("a client with the same username already exist in the ldap server")
            return False
        client_json_object_and_authority_certif = json.loads(client_json_object_and_authority_certif)
        client_json_object = client_json_object_and_authority_certif["client"]
        authority_certif = client_json_object_and_authority_certif["certif_authority"]
        # load client object
        client = Client.loadJson(client_json_object)
        # save client key and certif
        save_key_file(registration_directory+"/client.key",self.key_pair,passphrase)
        # save client certif
        save_certif_file(registration_directory+"/client.cert",string_to_certif(client.certification))
        # save authority certif 
        save_certif_file(registration_directory+"/CA.cert",string_to_certif(authority_certif))
        return True
    def register(self,registration_directory,nom,prenom,login,password,passphrase):
        self.fill_client_info(nom, prenom, login, password)
        self.generate_keypPair()
        self.fill_certification_request_info()
        self.set_up_socket()
        result = self.validate_with_pki(registration_directory,passphrase)
        self.my_socket.close()
        return result 
    

# reg = Resgistration()
# reg.register()


####################






# client=Clientf()
# client.sign=True
#
# if(client.authentification(Client(3333, 'cn3', 'sn3', 'uid3', 'pwd3'))):
#     client.start_listener(client.output)
#     # client.select_destination('uid3')
#     while(1):
#         a=input()
#         client.send(a)