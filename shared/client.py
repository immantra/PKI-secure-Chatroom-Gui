import json
from shared.openssl import *
class Client:

    def __init__(self,num=0,nom='',prenom='',login='',password='',certification=None):
        self.num = int(num.__str__())
        self.nom = nom.__str__()
        self.prenom = prenom.__str__()
        self.login = login.__str__()
        self.password = password
        self.certification = certification

    def __str__(self):
        return 'login:'+str(self.login)+'-'+str('nom:'+self.nom)+'-'+str('prenom:'+self.prenom)+'-'\
               +'numTelephone:' + str(self.num) + '-'+'password:'+self.password\
               +'-'+'certification:'+self.certification+'.'

    def serialise(self):
        attributes=dict(self.__dict__)
        # if((not isinstance(attributes['certification'],str)) and attributes['certification']!=None):
        #     attributes['certification']=certif_to_bytes(attributes['certification'])
        if(not isinstance(attributes['certification'],str) and attributes['certification']!=None):
            if hasattr(attributes['certification'], '_req'):
                attributes['certification']=certif_request_to_string(attributes['certification'])
            else:
                attributes['certification']=certif_to_string(attributes['certification'])
        return json.dumps(attributes)  # data serialized

    @staticmethod
    def loadJson(data):
        data_loaded = json.loads(data,strict=False)  # data loaded
        client=Client()
        client.__dict__.update(data_loaded)
        return client
