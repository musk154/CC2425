import socket
import sys

class NMS_Server:
    
    def start_udp_server(ip, port=12345):
        """
        Inicia um servidor UDP genérico.

        Args:
            ip (str): Endereço IP onde o servidor será executado.
            port (int): Porta onde o servidor irá escutar (padrão: 12345).
        """
        # Criação do socket UDP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            # Vincula o socket ao IP e à porta fornecidos
            server_socket.bind((ip, port))
            print(f"Servidor UDP escutando em {ip}:{port}...")

            # Loop principal para receber e responder mensagens
            while True:
                data, client_address = server_socket.recvfrom(1024)  # Tamanho do buffer de recepção
                print(f"Recebido de {client_address}: {data.decode()}")

                # Envia uma resposta ao cliente
                response = "Mensagem recebida!"
                server_socket.sendto(response.encode(), client_address)
                print(f"Resposta enviada para {client_address}")

        except Exception as e:
            print(f"Erro no servidor: {e}")
        finally:
            # Fecha o socket
            server_socket.close()
            print("Servidor encerrado.")


    # Obtém o IP a partir dos argumentos
    server_ip = sys.argv[1]

    # Inicia o servidor
    start_udp_server(server_ip)

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
    # Verifica se um argumento IP foi passado
    if len(sys.argv) < 2:
        print("Uso: python servidor_udp.py <IP>")
        sys.exit(1)
    
