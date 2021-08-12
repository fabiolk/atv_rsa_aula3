#! /usr/bin/env python

#codigo baseado na documentação
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#generation
#https://github.com/grakshith/p2p-chat-pytho

#1 na __name__ == '__main__': instancia a classe Client() e da .start() para chamar def run() de acordo com o que é determinado no metodo threading
#2 dentro de def run()instancia a classe Server() e chama a função gera_chave_rsa()
#3 na função gera_chave_rsa() crio a chave privada e depois a publica, serializo a chave publica, crio variaveis de controle 
#4 em seguida da start no Server e executa run()
#5 em self.sock.send(srv.public_key_byte) envia a chave publica 1 etapa
#6 laço while enquanto nao tiver outro cliente conectado
#

#inicio imports ex1
import socket
import sys
import time
import threading
import select
import traceback
#fim imports ex1

#inicio imports ex2
from cryptography.hazmat.primitives.asymmetric import rsa #para gera prived key/public key
from cryptography.hazmat.primitives import serialization #importada na serialização da chave publica
from cryptography.hazmat.primitives import hashes #aplica hash da chave simetrica/também usada para assinar uma mensagem onde quem possui a chave publica confirma a autenticidade
from cryptography.hazmat.primitives.asymmetric import padding #usado juntamente com o hash
from cryptography.hazmat.primitives.serialization import load_pem_public_key # usado para na obtenção da public key na verificação
from cryptography.fernet import Fernet
#fim imports ex2

from cryptography.exceptions import InvalidSignature # If the signature does not validate.

import warnings #warnings.filterwarnings(action, message='', category=Warning, module='', lineno=0, append=False)
warnings.filterwarnings("ignore") #"ignore" never print matching warnings

class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def gera_chave_rsa(self): #função para gerar chaves e variaveis
        #self para acessar as propriedades e metodos de uma instancia
        self.private_key = rsa.generate_private_key(
            #key_size describes how many bits long the key should be.
            #The public_exponent indicates what one mathematical property of the key generation will be.
            #Unless you have a specific reason to do otherwise, you should always use 65537.
            public_exponent=65537,
            key_size=2048,
        )

        self.public_key = self.private_key.public_key()#gera a chave publica a partir da privada

        self.public_key_byte = self.public_key.public_bytes(
            #serializa a chave publica para mandar em bytes e o que a indentifica é o fato de começar com '-----BEGIN PUBLIC KEY-----' 
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.chave_publica_destinatario = None 

        self.chave_publica_destinatario_byte = None #chave_publica_destinatario serializada para envio
        
        self.flag_chave_pub = False #sinaliza o recebimento da chave publica destinatario

        self.flag_assinatura = False #sinaliza o recebimento da assinatura

        self.flag_simetrica = False #sinaliza o recebimento da chave simetrica destinatario

        self.chave_simetrica_remetente = None
        
        self.chave_simetrica_destinatario = None 
        
        
    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        chunk = s #atualiza a cada mensagem  que chega do server
                        
                        decodifica_bytes = chunk.decode('unicode_escape')
                        #decodifica o formato de bytes

                        id_ini_chave_publi = '-----BEGIN PUBLIC KEY-----'
                        #identificador do inicio da chave publica descerializada

                        if decodifica_bytes.startswith(id_ini_chave_publi) and self.chave_publica_destinatario_byte is None:
                            #recebe a chave pública do servidor central
                            
                            self.chave_publica_destinatario_byte = chunk
                            
                            self.chave_publica_destinatario = load_pem_public_key(self.chave_publica_destinatario_byte)
                            #You can obtain a public key to use in verification using load_pem_public_key()
                            print('Recebeu a chave publica do destinatario')
                            
                        elif not decodifica_bytes.startswith(id_ini_chave_publi) and self.chave_simetrica_destinatario is None:
                            #recebe a chave simetrica
                            
                            #decripto a mensagem com a minha chave privada
                            self.chave_simetrica_destinatario = self.private_key.decrypt(
                                chunk,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None)
                                
                            )
                            print('Recebeu a chave simetrica do destinatario')
                            
                        elif not self.flag_assinatura and self.chave_simetrica_destinatario is not None:
                            #atesto se a chave simetrica nao foi alterada usando a verificação de assinatura
                            try:
                                #If the signature does not match, verify() will raise an InvalidSignature exception.
                                self.chave_publica_destinatario.verify(
                                    chunk,
                                    self.chave_simetrica_destinatario,
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH
                                    ),
                                    hashes.SHA256()
                                )
                                self.flag_assinatura = True
                                print('Assinatura da chave simétrica válida!')
                            except InvalidSignature:
                                print('Assinatura da chave simétrica inválida!')
                                break
                                                    
                        elif self.flag_assinatura:
                            #após todas as verificaçôes de segurança so é necessário criptografar a mensagem com a chave simétrica do destinário
                            f = Fernet(self.chave_simetrica_destinatario)
                            
                            print(f.decrypt(chunk).decode() + "\n>>")

                            self.flag_assinatura = False #sempre verifica se a assinatura simétrica não foi alterada
                            
                            
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg, srv):
        
        if not srv.flag_chave_pub and srv.chave_publica_destinatario_byte is not None:
            #troca a chave publica entre os clientes
            self.sock.send(srv.public_key_byte)
            srv.flag_chave_pub = True
            time.sleep(0.5)
            print('Enviou a chave publica do remetente para o servidor central\n')
            
        elif srv.flag_chave_pub:
            #ja trocou a chave publica
            if not srv.flag_simetrica:
                #gera chave simetrica, encripta com a pública do destino e envia
                srv.chave_simetrica_remetente = Fernet.generate_key()# gera chave simetrica
                
                chave_simetrica_encriptada = srv.chave_publica_destinatario.encrypt(
                    #encripta a chave simetrica com a chave publica do destino
                        srv.chave_simetrica_remetente,
                        padding.OAEP(mgf=padding.MGF1(
                        algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None)
                    )
                
                self.sock.send(chave_simetrica_encriptada)
                #envia a chave simétrica por um meio não seguro, porém encriptada com a chave pública do destinatário
                srv.flag_simetrica = True
                time.sleep(0.5)
                print('Encriptou a chave simetrica com a chave publica do destinatario e enviou \n')
                
            f = Fernet(srv.chave_simetrica_remetente)#Chave simetrica

            assinatura = srv.private_key.sign(
                srv.chave_simetrica_remetente,
                padding.PSS(mgf=padding.MGF1(
                    hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                ) #assina a chave simétrica com a chave privada do remetente
            
            self.sock.send(assinatura)
            print('Envio a assinatura (assinei o hash da chave simetrica com minha chave privada)\n')
            time.sleep(0.5)
            
            mensagem = self.sock.send(f.encrypt(msg))#envia a mensagem
            

    def run(self):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            #host = input("Enter the server IP \n>>")
            #port = int(input("Enter the server Destination Port\n>>"))
            host = '127.0.0.1'
            port = 5535
        except EOFError:
            print("Error")
            return 1

        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.gera_chave_rsa()#chama função
        print("Gerou chaves RSA")
        srv.start()
        self.sock.send(srv.public_key_byte)#envia a chave publica para o server
        print("Enviou para o servidor a chave publica")
        time.sleep(0.5)
        while not srv.flag_chave_pub: #enquanto a funcao client não tiver outro client
            time.sleep(0.5)
            self.client(host, port, b'', srv)
        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = user_name + ': ' + msg
            data = msg.encode()
            self.client(host,port,data,srv)
        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()
