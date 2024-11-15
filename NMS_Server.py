import socket

class NMS_Server:
    def start_udp_server(self):
        # Configurações do servidor
        IP = "127.0.0.1"  # Endereço IP do servidor (pode ser 0.0.0.0 para escutar em todas as interfaces)
        PORT = 12345      # Porta onde o servidor vai escutar

        # Criação do socket UDP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Vincula o socket ao endereço e à porta
        server_socket.bind((IP, PORT))

        print(f"Servidor UDP escutando em {IP}:{PORT}...")

        # Loop principal do servidor para receber e responder a pacotes
        while True:
            # Recebe dados do cliente (1024 é o tamanho do buffer)
            data, client_address = server_socket.recvfrom(1024)
            print(f"Recebido de {client_address}: {data.decode()}")

            # Responde ao cliente com uma mensagem
            response = "Mensagem recebida!"
            server_socket.sendto(response.encode(), client_address)
            print(f"Resposta enviada para {client_address}")

        # Se quiser parar o servidor, use Ctrl+C

    def start_tcp_server(self):# Configurações do servidor
        IP = "127.0.0.1"  # Endereço IP do servidor (pode ser 0.0.0.0 para escutar em todas as interfaces)
        PORT = 12346      # Porta onde o servidor vai escutar

        # Criação do socket TCP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Vincula o socket ao endereço e à porta
        server_socket.bind((IP, PORT))

        # Define o número de conexões que podem ficar em espera
        server_socket.listen(5)
        print(f"Servidor TCP escutando em {IP}:{PORT}...")

        while True:
            # Aceita uma nova conexão
            client_socket, client_address = server_socket.accept()
            print(f"Conexão estabelecida com {client_address}")

            # Recebe dados do cliente
            data = client_socket.recv(1024)  # Tamanho do buffer de recepção em bytes
            print(f"Recebido de {client_address}: {data.decode()}")

            # Envia uma resposta ao cliente
            response = "Mensagem recebida!"
            client_socket.send(response.encode())

            # Fecha a conexão com o cliente
            client_socket.close()
            print(f"Conexão com {client_address} encerrada")

if __name__ == "__main__":
    server = NMS_Server()
    #server.start_udp_server()
    server.start_tcp_server()

