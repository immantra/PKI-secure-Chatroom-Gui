from shared.client import Client
from ldap3 import *

from shared.globle import ldaplogin, ldap_base, ldap_password


class LDAP_server:
    def __init__(self, uri='ldap://localhost', login=ldaplogin, password=ldap_password):
        self.server = Server(uri)
        self.ldap_base = ldap_base
        self.connection = Connection(self.server, user=login, password=password, auto_bind=True)


    def create(self,client:Client):
        # create a client in LDAP server
        #Return TRUE if a new entry for client is created
        # Return FALSE if the entry already exists or is not created
        classObjects=['inetOrgPerson','person']
        return self.connection.add('uid={},{}'.format(client.login, self.ldap_base), classObjects,
                      {'cn': client.nom, 'sn': client.prenom, 'userPassword': client.password,
                       'telephoneNumber': client.num, 'description': client.certification})



    def findClient(self,login):
        try:
            self.connection.search(self.ldap_base, '(uid='+login+')'
                                , attributes=['uid', 'cn', 'sn', 'userPassword', 'telephoneNumber', 'description'])
            values=self.connection.entries[0]
            # print(values)

            return Client(values['telephoneNumber'], values['cn'], values['sn'], values['uid'],
                          values['userPassword'].__str__().split('\'')[1], values['description'][0])
        except:
            return None


# # Test scénario , add client then get it from ldap server
# l=LDAP_server()
# client = Client(3333, 'cn3', 'sn3', 'uid3', 'pwd3', 'certif3')
# created=l.create(client)
# print('Is a new entry created ? %s'%created)
# print(l.findClient('uid3'))