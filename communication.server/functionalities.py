from shared.client import Client
from shared.globle import *
from shared.ldap import *
from shared.openssl import *

from OpenSSL import SSL
import threading
import sys, os, select, socket

from shared.openssl import bytes_to_certif
import base64

class ClientThread(threading.Thread):

    def __init__(self, ip, port, socket:SSL.Connection,output,addClient,removeClient):
        threading.Thread.__init__(self)
        self.source = ip+":"+str(port)
        self.socket = socket
        self.output=output
        self.addClient=addClient
        self.removeClient=removeClient



    def run(self):
        try:
            json = self.socket.recv(buffersize).decode("utf-8")
        except Exception:
            return
        client=Client.loadJson(json)
        self.client = Server.authentification(client,self.socket.get_peer_certificate())
        if (isinstance(self.client,Client)):
            try:
                self.socket.send("TRUE")
                self.addClient(self.source,self)
                while 1:
                    msg = self.socket.recv(buffersize).decode("utf-8")
                    self.output(self.source,msg)
            except SSL.Error:
                print ('Connection died unexpectedly')
        else:
            self.socket.send(self.client)

        self.removeClient(self.source)




class Server:

    ldap_server = LDAP_server()

    def __init__(self, port=portCS, nb=connection_nb_CS,key='keys/server.key',cert='keys/server.cert',authourity='keys/CA.cert'):
        # Initialize context
        self.clients = {}
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_options(SSL.OP_NO_SSLv2)
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)  # Demand a certificate
        ctx.use_privatekey_file(os.path.join(key))
        ctx.use_certificate_file(os.path.join(cert))
        ctx.load_verify_locations(os.path.join(authourity))

        # Set up server
        self.server = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.server.bind(('', port))
        self.server.listen(nb)

    def __del__(self):
        for key in self.clients:
            try:
                self.clients[key].socket.shutdown()
                self.clients[key].socket.close()
            except Exception:
                return
            try:
                del self.clients[key]
            except Exception:
                return
        self.server.close()

    def listen(self):
        try:
            connection, address=self.server.accept()
            client=ClientThread(address[0],address[1],connection,self.writeMsg,self.addClient,self.removeClient)
            client.start()
        except Exception as e:
            print(e)


    def writeMsg(self,source,msg,destination='ALL'):
        if(destination=='ALL'):
            for id,client in self.clients.items():
                if(id!=source):
                    client.socket.send(msg)
                    print(msg)
        return

    def addClient(self,key,object):
        for id, client in self.clients.items():
            client.socket.send(newpettern+":"+key+'/'+object.client.login+'||'+object.client.certification)
        for id, client in self.clients.items():
            object.socket.send(newpettern+":"+key+'/'+client.client.login+'||'+client.client.certification)
        print("connect: "+key+'/'+object.client.login)
        self.clients[key] = object
        return

    def removeClient(self,key):
        o=None
        try:
            self.clients[key].socket.close()
        except Exception:
            return
        try:
            o = self.clients[key]
            del self.clients[key]
        except Exception:
            return
        try:
            for id, client in self.clients.items():
                client.socket.send(deletpattern+":"+key+'/'+o.client.login)
        except Exception as e:
            print(e)
        if(o!=None):
            print("deconnect: "+key+'/'+o.client.login)

    @staticmethod
    def authentification(client,certif):
        certif=certif_to_string(certif)
        cl = Server.ldap_server.findClient(client.login)
        if cl == None:
            return "user does not exist"
        else:
            if hash_SHA512(client.password) == cl.password :
                if(certif==cl.certification):
                    return cl
                return "certification incorrect"
            return "password incorrect"



server=Server()
while 1:
    server.listen()

