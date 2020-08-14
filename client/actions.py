
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import pyqtSignal, QObject, QCoreApplication
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QApplication, QLineEdit, QInputDialog

from client.AppGUI import Ui_UserWindow
from client.functionalities import Clientf, Resgistration

from shared.client import Client


class Action(QObject):
    displayFun = pyqtSignal(str)
    ajouterClient=pyqtSignal(str)
    deleteClient=pyqtSignal(str)
    def __init__(self, gui: Ui_UserWindow):
        super().__init__()
        self.gui=gui
        self.connection_tab(False)
        self.gui.keys_dir_btn.clicked.connect(self.select_key_directory)
        self.gui.login_btn.clicked.connect(self.login)
        self.gui.send_btn.clicked.connect(self.send)
        self.gui.signCheck.stateChanged.connect(self.sign_change)
        self.gui.file_selection_btn.clicked.connect(self.select_registration_directory)
        self.gui.register_btn.clicked.connect(self.register)
        self.directory=None
        self.gui.password_login_input.setEchoMode(QLineEdit.Password)
        self.registration_directory = None
        self.gui.clientsLists.addItem("all users")
        self.gui.clientsLists.currentTextChanged.connect(self.userSelect)
    def select_key_directory(self):
        self.directory = str(QFileDialog.getExistingDirectory(self.gui.centralwidget, "Select Directory"))
        self.gui.label_directory.setText(self.directory)

    def select_registration_directory(self):
        self.registration_directory = str(QFileDialog.getExistingDirectory(self.gui.centralwidget, "Select Directory"))
        self.gui.public_key_file_input.setText(self.registration_directory)

    def sign_change(self):
        self.client.sign=not self.client.sign

    def send(self):
        self.client.send(self.gui.text_input.text())
        text=self.gui.text_output.toPlainText()
        if(text!=""):
            text=self.gui.text_output.toHtml()
        self.gui.text_output.setText(text+"<span style=\"color: red\"> me: </span>"+self.gui.text_input.text()+"\n")
        self.gui.text_input.setText("")

    def login(self):
        if(self.directory==None or self.directory==''):
            self.pop_up("Error","select keys directory ","with client.key, client.cert,CA.cert")
            return

        login=self.gui.username_login_input.text()
        password=self.gui.password_login_input.text()
        if(login=="" or password==""):
            self.pop_up("Error", "specifier login et password")
            return
        try:
            self.client.__del__()
            del self.client
        except Exception as e:
            print(e)
        try:
            self.client=Clientf(key=self.directory+'/client.key',cert=self.directory+'/client.cert',authourity=self.directory+'/CA.cert',passphrase=self.passphrase)
        except FileNotFoundError as e:
            self.pop_up("Error", "file not found", e.__str__())
            return
        except Exception as e:
            if(e.__str__()=="Cancel"):
                return
            self.pop_up("Error", "bad passphrase", e.__str__())
            return
        auth=self.client.authentification(Client(login=login,password=password))
        if(auth==True):
            self.displayFun.connect(self.display_result)
            self.ajouterClient.connect(self.add_client)
            self.deleteClient.connect(self.del_client)
            self.client.start_listener(self.displayFun.emit,self.ajouterClient.emit,self.deleteClient.emit)
            self.connection_tab(True)
        else:
            del self.client
            self.pop_up("Authentification error", auth)

    def register(self):
        if self.registration_directory == None or self.registration_directory == '':
            self.pop_up("Error", "select a directory","to save key and certificats")
            return
        firstName= self.gui.fname_input.text()
        lastName = self.gui.lname_input.text()
        login=self.gui.username_input.text()
        password=self.gui.password_input.text()
        #self.direcory
        if login=="" or password=="" or firstName == "" or lastName == "":
            self.pop_up("Error", "specifier first name, last name, login et password ")
            return

        print(firstName, lastName, login, password, self.registration_directory)
        reg = Resgistration()
        try:
            registred = reg.register(self.registration_directory, lastName, firstName, login, password, self.passphrase_write)
        except Exception as e:
            if(e.__str__()=="Cancel"):
                return
            self.pop_up("Error", "bad passphrase", e.__str__())
            return e


        if registred == True:
            self.pop_up("succeded", "registration succeded")
        else:
            self.pop_up("errr","Registration error")
            return



    def del_client(self,login):
        self.gui.clientsLists.setCurrentText(login)
        index=self.gui.clientsLists.currentIndex()
        self.gui.clientsLists.setCurrentIndex(0)
        self.gui.clientsLists.removeItem(index)

    def add_client(self,text):
        self.gui.clientsLists.addItem(text)

    def get_client_info(self):
        c=Client(1,self.gui.fname_input.text(),self.gui.lname_input.text(),self.gui.username_input.text(),self.gui.password_input.text())

    def connection_tab(self,state):
        self.gui.tabWidget.setTabEnabled(2, state)
        self.gui.tabWidget.setTabEnabled(0,not state)
        self.gui.tabWidget.setTabEnabled(1 ,not state)
        if(state):
            self.gui.tabWidget.setCurrentIndex(2)

    def display_result(self,msg):
        text = self.gui.text_output.toPlainText()
        if (text != ""):
            text = self.gui.text_output.toHtml()
        self.gui.text_output.setText(text+msg+"\n")

    def userSelect(self,login):
        self.client.select_destination(login)

    def closeAll(self):
        try:
            self.client.__del__()
        except Exception as e:
            return
        print("app closed")

    def passphrase(self,rwflag):
        input,ok=QInputDialog().getText(self.gui.centralwidget,"passphrase dilog", "enter passphrase", QLineEdit.NoEcho)
        if(not ok):
            raise Exception("Cancel")
        return input.encode()

    def passphrase_write(self):
        input, ok = QInputDialog().getText(self.gui.centralwidget, "passphrase dilog", "enter passphrase",
                                           QLineEdit.NoEcho)
        return input.encode()

    def pop_up(self,title,text,detail=None):
        msg = QMessageBox(self.gui.centralwidget)
        msg.setIcon(QMessageBox.Information)
        msg.setText(text)
        if(detail!=None):
            msg.setDetailedText(detail)
        msg.setWindowTitle(title)
        msg.show()


