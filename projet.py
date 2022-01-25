import sqlite3
import getpass
import hashlib
import re
import smtplib, ssl
import math, random
# from elgamal import elgamal
from time import sleep
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA,ElGamal
from Crypto.Util.number import long_to_bytes,bytes_to_long

con = sqlite3.connect('table.db')
cur = con.cursor()
# cur.execute("delete from users where email = ? ", ('yassinlassoued1@gmail.com',))
# con.commit()

# elgamalKeys = elgamal.generate_keys(128)
# key = RSA.generate(2048)
# f = open('mykey.pem','wb')
# f.write(key.export_key('PEM'))
# f.close()

# cur.execute('''CREATE TABLE users
#                (Nom text, Prenom text, Email text, pwd text)''')


print("Bienvenue ")

def start():

    while(1):
        print("Choisir une option :")
        print(" 1- S'inscrire")
        print(" 2- Se connecter")
        print(" 3- Quitter")
        option = int(input(">"))
        if(option not in {1,2,3}):
            print("Veuillez vérifier votre choix ")
        else:
            break
    return option

def signup():
    while(1):
        print(" ------- S'inscrire  -------")
        nom = input("Nom ")
        prenom = input("Prenom : ")
        email = input("Email : ")
        pwd = getpass.getpass("Mot de passe :")
        pwd2 = getpass.getpass("Confirmer Mot de passe :")
        if(pwd==pwd2):
            break
        else:
            print("Erreur! : Veuillez vérifier votre mot de passe")
    mdp = hashlib.sha256(pwd.encode()).hexdigest()
    cur.execute("insert into users values (?, ?, ?, ?)", (nom,prenom,email,mdp))
    con.commit()
    # cur.execute("select * from users ")
    # print(cur.fetchall())

port = 587  # For starttls
smtp_server = "smtp.gmail.com"
def sendVerificationCode(receiver_email):
    code = ""
    for i in range(6):
	    code += str(int(math.floor(random.random() * 10)))
    message = "This is your verification code:  " + code
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(EMAIL_SERVER, PASSWORD)
        server.sendmail(EMAIL_SERVER, receiver_email, message)
    return code

def signin():
    while(1):
        print(" --------- Se connecter--------")
        email = input("Email : ")
        pwd = getpass.getpass("Mot de passe :")
        data = cur.execute("select * from users where email = ?",(email,)).fetchall()
        if(len(data)==0):
            print("Erreur! : Veuillez vérifier vos données svp")
        else:
            hash = data[0][3]
            if(hash==hashlib.sha256(pwd.encode()).hexdigest()):
                return data[0]
                # print("ok")
                # ver = sendVerificationCode(email)
                # verCli = input(" donner le code de verification! ")
                # if(verCli == code):
                #     print("hoooraaay welcome")
                # else:
                #     print("Erreur! : Veuillez vérifier vos données svp")
            else:
                print("Erreur! : Veuillez vérifier vos données svp")

def code():
    print("   Codage d'un message")
    msg = input("Donnez le message a coder")
    print(msg.encode().hex())
    sleep(1)

def decode():
    print("   Decodage d'un message")
    msg = input("Donnez le message a décoder")
    print(bytes.fromhex(msg).decode('utf-8'))
    sleep(1)

def Md5_crack(message):
    with open('insat.dic') as f:
        for p in f.readlines():
            if(hashlib.md5(p.strip().encode()).hexdigest()==message):
                return p
        return 'not found'
def SHA1_crack(message):
    with open('insat.dic') as f:
        for p in f.readlines():

            if(hashlib.sha1(p.strip().encode()).hexdigest()==message):
                return p
        return 'not found'
def SHA256_crack(message):
    with open('insat.dic') as f:
        for p in f.readlines():

            if(hashlib.sha256(p.strip().encode()).hexdigest()==message):
                return p
        return 'not found'
def crack_hash():
    print("craquage d'un message")
    while 1:
        print("   a- MD5 ")
        print("   b- SHA1")
        print("   c- SHA256")
        choix= input("-->")
        if(choix not in {'a','b','c'}):
            print("Erreur! : Veuillez vérifier votre choix svp")
        else:

            hash =input("entrez le hash svp ")
            if(choix=='a'):
                result = Md5_crack(hash)
            elif(choix=='b'):
                result= SHA1_crack(hash)
            else:
                result = SHA256_crack(hash)
            break
    return result



KEY_DES = b"DESDESDE"

def des():
    cipher = DES.new(KEY_DES,DES.MODE_ECB)
    while 1:
        print("   i- chiffrement ")
        print("   ii- déchiffrement")
        choix= input("-->")
        if(choix not in {'i','ii'}):
            print("Erreur! : Veuillez vérifier votre choix svp")
        else:
            if(choix=='i'):
                msg = input("Donnez le message a chiffrer")

                msg = pad(msg.encode(),8)
                print(cipher.encrypt(msg).hex())
                sleep(1)
            else:
                msg = input("Donnez le message a déchiffrer")
                print(msg.encode())
                res = unpad(cipher.decrypt(bytes.fromhex(msg)),8).decode('utf-8')
                print(res)
                sleep(1)
            break

KEY_AES= b'aess'*8
iv = b'5cqSH5rgCzOXMgZa'

def aes256():
    cipher = AES.new(KEY_AES,AES.MODE_CBC,iv)
    while 1:
        print("   i- chiffrement ")
        print("   ii- déchiffrement")
        choix= input("-->")
        if(choix not in {'i','ii'}):
            print("Erreur! : Veuillez vérifier votre choix svp")
        else:
            if(choix=='i'):
                msg = input("Donnez le message a chiffrer")

                msg = pad(msg.encode(),16)
                print(cipher.encrypt(msg).hex())
                sleep(1)
            else:
                msg = input("Donnez le message a déchiffrer")
                print(msg.encode())
                res = unpad(cipher.decrypt(bytes.fromhex(msg)),16).decode('utf-8')
                print(res)
                sleep(1)
            break
def rsa():
    f = open('mykey.pem','r')
    key = RSA.import_key(f.read())
    while 1:
        print("   i- chiffrement ")
        print("   ii- déchiffrement")
        choix= input("-->")
        if(choix not in {'i','ii'}):
            print("Erreur! : Veuillez vérifier votre choix svp")
        else:
            if(choix=='i'):
                msg = input("Donnez le message a chiffrer :  ")
                msg = bytes_to_long(msg.encode())
                encrypted = pow(msg,key.e,key.n)
                print(long_to_bytes(encrypted).hex())
            else:
                msg = input("Donnez le message a déchiffrer :  ")
                encrypted = bytes_to_long(bytes.fromhex(msg))
                msg = pow(encrypted,key.d,key.n)
                print("Resultat : ",long_to_bytes(msg).decode('utf-8'))
            break


def elgamal():
    return 1


import socket, threading
def client():

    nickname = input("Choose your nickname: ")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      #socket initialization
    client.connect(('127.0.0.1', 7976))                             #connecting client to server

    def receive():
        while True:                                                 #making valid connection
            try:
                message = client.recv(1024).decode('ascii')
                if message == 'NICKNAME':
                    client.send(nickname.encode('ascii'))
                else:
                    print(message)
            except:                                                 #case on wrong ip/port details
                print("An error occured!")
                client.close()
                break
    def write():
        while True:
            q = input('')                                                 #message layout
            message = '{}: {}'.format(nickname, q)
            client.send(message.encode('ascii'))
            if (q=='Q'):
                client.close()

    receive_thread = threading.Thread(target=receive)               #receiving multiple messages
    receive_thread.start()
    write_thread = threading.Thread(target=write)                   #sending messages
    write_thread.start()





def menu():
    while(1):
        print("Choisir une option :")
        print(" 1- Codage et décodage d'un message")
        print(" 2- hashage d'un message")
        print(" 3- craquage d'un message hashé")
        print(" 4- chiffrement et déchiffrement symétrique d'un message")
        print(" 5- chiffrement et déchiffrement asymétrique d'un message")
        print(" 6- Communication sécurisé entre deux clients")
        print(" 7- Quitter")
        c = int(input("-->"))

        if(c==1):
            while 1:
                print("   a- Codage ")
                print("   b- Décodage")
                choix= input("-->")
                if(choix not in {'a','b'}):
                    print("Erreur! : Veuillez vérifier votre choix svp")
                else:
                    if(choix=='a'):
                        code()
                    else:
                        decode()
                    break
        elif(c==2):
            while 1:
                print("   a- MD5 ")
                print("   b- SHA1")
                print("   c- SHA256")
                choix= input("-->")
                if(choix not in {'a','b','c'}):
                    print("Erreur! : Veuillez vérifier votre choix svp")
                else:
                    if(choix=='a'):
                        print("   MD5")
                        mmsg = input("Donnez le message a hasher : ")
                        print(hashlib.md5(mmsg.encode()).hexdigest())
                    elif(choix=='b'):
                        print("   SHA1")
                        mmsg = input("Donnez le message a hasher : ")
                        print(hashlib.sha1(mmsg.encode()).hexdigest())
                        decode()
                    else:
                        print("   SHA256")
                        mmsg = input("Donnez le message a hasher : ")
                        print(hashlib.sha256(mmsg.encode()).hexdigest())
                    break
        elif( c==3):
            print(crack_hash())
        elif (c==4):
            while 1:
                print("   a- DES ")
                print("   b- AES256")
                choix= input("-->")
                if(choix not in {'a','b'}):
                    print("Erreur! : Veuillez vérifier votre choix svp")
                else:
                    if(choix=='a'):
                        des()
                    else:
                        aes256()
                    break
        elif (c==5):
            while 1:
                print("   a- RSA ")
                print("   b- ELgamal")
                choix= input("-->")
                if(choix not in {'a','b'}):
                    print("Erreur! : Veuillez vérifier votre choix svp")
                else:
                    if(choix=='a'):
                        rsa()
                    else:
                        elgamal()
                    break
        elif(c==6):
            print("If you want to exist the chat print Q")
            client()
            while(1):
                i = input()
                if (i == 'Q'):
                    break












def main():
    while 1:
        info =0
        option = start()
        if(option==1):
            signup()
        if(option==2):
            info =signin()
        if(option==3):
            break
        if (info):
            print("   *****Bienvenue",info[0],'****')
            menu()
if __name__=="__main__":
    main()
con.commit()
con.close()
