#! /usr/bin/env python

#codigo baseado no site da biblioteca https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#generation
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
from cryptography.hazmat.primitives.asymmetric import rsa #importada na geração de chave privada
from cryptography.hazmat.primitives import serialization #importada na serialização da chave publica
from cryptography.hazmat.primitives import hashes #A private key can be used to sign a message. This allows anyone with the public key to verify that the message was created by someone who possesses the corresponding private key.
from cryptography.hazmat.primitives.asymmetric import padding #A private key can be used to sign a message. This allows anyone with the public key to verify that the message was created by someone who possesses the corresponding private key.
from cryptography.hazmat.primitives.serialization import load_pem_public_key # necessary to check that the private key associated with a given public key was used to sign that specific message.
from cryptography.fernet import Fernet
#fim imports ex2


class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def gera_chave_rsa(self): #função para gerar chaves
        #self para acessar as propriedades e metodos de uma instancia
        self.private_key = rsa.generate_private_key(
            #key_size describes how many bits long the key should be.
            #The public_exponent indicates what one mathematical property of the key generation will be. Unless you have a specific reason to do otherwise, you should always use 65537.
            public_exponent=65537,
            key_size=2048,
        )

        self.public_key = self.private_key.public_key()#gera a chave publica a partir da privada

        self.public_key_byte = self.public_key.public_bytes(
            #serializa a chave publica para mandar em bytes e o que a indentifica é o fato de começar com '-----BEGIN PUBLIC KEY-----' 
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.chave_publica_segundo_cliente = None #armazena a chave publica recebida

        self.chave_publica_segundo_cliente_byte = None
        
        self.chave_simetrica_segundo_cliente = None #variavel que armazena a chave simetrica recebida

        self.flag_chave_pub = False #variavel que sinaliza o recebimento da chave publica

        self.flag_assinatura = False #variavel para saber se chegou a assinatura

        self.enviou_sim = False #variavel para saber se ja chegou a chave simetrica

        self.flag_chave_simetrica = False #variavel que sinaliza o recebimento da chave simetrica

        self.chave_simetrica_remetente = None #variavel que armazena a chave simetrica do client 1
        
        self.chave_simetrica_destinatario = None #variavel que armazena a chave simetrica do client 2
        
        
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

                        if decodifica_bytes.startswith(id_ini_chave_publi) and self.chave_publica_segundo_cliente_byte is None:#ainda nao recebeu chave publica
                            
                            self.chave_publica_segundo_cliente_byte = chunk
                            
                            self.chave_publica_segundo_cliente = load_pem_public_key(self.chave_publica_segundo_cliente_byte)
                            # If you have a public key, a message,a signature, and the
                            #signing algorithm that was used you can check that the private
                            #key associated with a given public key was used to sign that
                            #specific message. You can obtain a public key to use in
                            #verification using load_pem_public_key()
                            print(decodifica_bytes)
                            
                        elif not decodifica_bytes.startswith(id_ini_chave_publi) and self.chave_simetrica_segundo_cliente is None:
                            #Nao trocaram chave simetrica ainda
                            # se ainda não tivermos a chave simétrica, então precisamo decriptá-la
                            self.chave_simetrica_segundo_cliente = self.private_key.decrypt(
                                chunk,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None)
                                
                            )
                        elif not self.flag_assinatura and self.chave_simetrica_destinatario is not None:
                            try:
                                self.chave_publica_client_2.verify(
                                    chunk,
                                    self.chave_simetrica_destinatario,
                                    padding.PSS(mgf=padding.MGF1(
                                        hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH),
                                        hashes.SHA256()
                                    )
                                self.flag_assinatura = True
                                
                            except InvalidSignature:
                                print('Assinatura da chave simétrica inválida!')
                                break
                                                    
                        elif self.flag_assinatura:
                            
                            f = Fernet(self.chave_simetrica_destinatario)
                            
                            print(f.decrypt(chunk).decode() + "\n>>")
                            
                            self.flag_assinatura = False
                            
                            #print(chunk.decode() + '\n>>')
                except:
                    traceback.print_exc(file=sys.stdout)
                    break


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg, srv):
        if not srv.flag_chave_pub and srv.chave_publica_segundo_cliente_byte is not None:
            
            self.sock.send(srv.public_key_byte)
            srv.flag_chave_pub = True
            time.sleep(0.5)
            
        elif srv.flag_chave_pub:
            if not srv.enviou_sim:
                srv.chave_simetrica_remetente = Fernet.generate_key()# gera chave simetrica

                chave_simetrica_encriptada = srv.chave_publica_segundo_cliente.encrypt(
                    #Encryption
                    srv.chave_simetrica_remetente,
                    padding.OAEP(mgf=padding.MGF1(
                        algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None)
                    )
                
                self.sock.send(chave_simetrica_encriptada) # envia a chave simétrica por um meio não seguro (seguro), porém com a chave encriptada por meio da chave pública do outro cliente
                srv.flag_chave_simetrica = True
                time.sleep(0.5)
                
            f = Fernet(srv.chave_simetrica_remetente)#Chave simetrica encryptada

            assinatura = srv.private_key.sign(
                srv.chave_simetrica_remetente,
                padding.PSS(mgf=padding.MGF1(
                    hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                ) # assina a chave simétrica (desencriptada)
            
            self.sock.send(assinatura)
            time.sleep(0.5)
            mensagem = self.sock.send(f.encrypt(msg))# Mensagem ultimo passo
            
        #sent = self.sock.send(msg)
        # print "Sent\n"

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
        #user_name = 'f'
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.gera_chave_rsa()#chama função
        srv.start()#inicia server
        self.sock.send(srv.public_key_byte)#passo 1 envia a chave publica para o server
        time.sleep(0.5)
        while not srv.flag_chave_pub: #enquanto a funcao client tiver outro client
            time.sleep(0.5)
            self.client(host, port, b'', srv)
            print("Segundo client conectou")
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
