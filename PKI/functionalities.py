from Crypto.Util import asn1
from shared.globle import *
from shared.client import Client
from shared.openssl import *
from shared.ldap import *
import os
import socket
import json


class CertificationServer:
    def __init__(self,port=portPKI,nb_connections=connection_nb_PKI,keyfile='keys/CA.pkey',certificatefile='keys/CA.cert'):
        if os.path.isfile(keyfile):
            self.key = load_key_file(keyfile)
        else:
            self.key = create_keyPair(crypto.TYPE_RSA, 1024)
            save_key_file(keyfile,self.key)

        if os.path.isfile(certificatefile):
            self.certif = load_certi_file(certificatefile)
            pub=self.certif.get_pubkey()
            # Only works for RSA (I think)
            if pub.type() != crypto.TYPE_RSA or self.key.type() != crypto.TYPE_RSA:
                raise Exception('Can only handle RSA keys')

            # This seems to work with public as well
            pub_asn1 = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pub)
            priv_asn1 = crypto.dump_privatekey(crypto.FILETYPE_ASN1, self.key)

            # Decode DER
            pub_der = asn1.DerSequence()
            pub_der.decode(pub_asn1)
            priv_der = asn1.DerSequence()
            priv_der.decode(priv_asn1)

            # Get the modulus
            pub_modulus = pub_der[1]
            priv_modulus = priv_der[1]

            if pub_modulus != priv_modulus:
                self.certif=None

        if(not hasattr(self, 'certif') or self.certif==None):
            careq = create_certRequest(self.key, CN='Certificate Authority')
            self.certif = create_certificate(careq, careq, self.key, 0, 0, 60 * 60 * 24 * 365 * 5)
            save_certif_file(certificatefile,self.certif)


        self.ldap_server = LDAP_server()

        #run certification server
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('',port))
        self.server.listen(nb_connections)

    def __del__(self):
        self.server.close()

    def listen(self):
        connection, address = self.server.accept()
        client_json_object = connection.recv(buffersize).decode("utf-8") # recieved a client object with his certif request
        client = Client.loadJson(client_json_object)
        # verify identity: skype, phone call, visit
        #create certif & sign up client
        client.certification = string_to_certif_request(client.certification)
        client = self.signUp(client)
        if client==None:
            connection.send(b"error client exist")
            return
        client_and_ca = json.dumps(
            {
                "client": client.serialise(),
                "certif_authority": certif_to_string((self.certif))
            }
            )
        connection.send(client_and_ca.encode('utf-8'))

    def signUp(self, client:Client):
        certif = create_certificate(client.certification, self.certif, self.key, 0, 0, 60 * 60 * 24 * 365 * 5)
        client.certification = certif_to_string(certif)
        client.password=hash_SHA512(client.password)
        if(self.ldap_server.create(client)):
           return client
        else:
           return None

    def server_certif(self,request):
        certif= create_certificate(request, self.certif, self.key, 0, 0, 60 * 60 * 24 * 365 * 5)
        return  certif_to_bytes(certif)


# generate client certification
# PKI=CertificationServer()
# k=create_keyPair()
# req=create_certRequest(k,CN='Certification client')
# client = Client(3333, 'cn3', 'sn3', 'uid2', 'pwd2', req)
# client=PKI.signUp(client)
# save_key_file("client.key",k,passphrase="admin")
# save_certif_file("client.cert",bytes_to_certif(client.certification))


# generate server certification
# PKI=CertificationServer()
# k=create_keyPair()
# req=create_certRequest(k,CN='Certification server')
# certif=PKI.server_certif(req)
# save_key_file("server.key",k,passphrase="admin")
# save_certif_file("server.cert",bytes_to_certif(certif))
# save_certif_file("server.cert",string_to_certif(certif))

certification_server = CertificationServer()
while 1:
    certification_server.listen()

