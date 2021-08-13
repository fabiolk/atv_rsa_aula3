# Criptografia por chave assimétrica em python
 
  Trabalho realizado como parte da disciplina de auditoria e segurança de sistemas.
 
## Obejtivos
* Fazer melhorias no código disponibilizado em https://github.com/grakshith/p2p-chat-python de modo a implementar a funcionalidade de chaves assimétricas
* Fazer a troca encriptada de mensagem entre dois clientes
* Garantir confidencialidade, integridade e autenticidade
* Implementar algoritmo RSA
* Transmitir as chaves simétricas usando criptografia assimétrica e verificar integridade e autenticidade das mensagens
* Interceptar pacotes usando wireshark e comprovar que as mensagens não estão legíveis   
  
## Conhecimentos usados
* Python
* Criptografia assimétrica
* Algoritmo RSA
* Sockets 
* Threading
* Wireshark

## Melhorias
* Este programa comparado ao código de aplicação de chave simétrica não precisa gravação da mesma em texto pleno ou em arquivo, porém, tem como desvantagem a comunicação entre somente 2 clientes.
* E como melhoria sugere fazer o envio da assinatura concatenado a mensagem; Reduzir a quantidade de variáveis de flag; Evitar redundância da chamada da função de troca da chave pública; Adicionar mais eventos de verificação try/catch.
