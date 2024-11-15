import socket

class NMS_Agent:
    def start_udp_server(self):
# Configurações do servidor (mesmo IP e porta do servidor UDP)
        SERVER_IP = "127.0.0.1"
        SERVER_PORT = 12345

        # Criação do socket UDP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Mensagem que será enviada ao servidor
        message = "Olá, servidor!"

        try:
            # Envia a mensagem ao servidor
            print(f"Enviando mensagem para {SERVER_IP}:{SERVER_PORT}...")
            client_socket.sendto(message.encode(), (SERVER_IP, SERVER_PORT))
            
            # Aguardando a resposta do servidor (1024 é o tamanho do buffer)
            data, server_address = client_socket.recvfrom(1024)
            print(f"Recebido do servidor {server_address}: {data.decode()}")

        finally:
            # Fecha o socket
            client_socket.close()
    
   # Configurações do servidor (IP e porta onde o servidor está escutando)
    def start_tcp_server(self):
        SERVER_IP = "127.0.0.1"
        SERVER_PORT = 12346

        # Criação do socket TCP
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Conexão ao servidor
            client_socket.connect((SERVER_IP, SERVER_PORT))
            print(f"Conectado ao servidor {SERVER_IP}:{SERVER_PORT}")

            # Mensagem que será enviada ao servidor
            message = "Olá, servidor!"
            client_socket.send(message.encode())
            print(f"Mensagem enviada: {message}")

            # Recebe a resposta do servidor
            response = client_socket.recv(1024)  # Tamanho do buffer de recepção em bytes
            print(f"Resposta do servidor: {response.decode()}")

        finally:
            # Fecha o socket
            client_socket.close()
            print("Conexão encerrada")

if __name__ == "__main__":
    agent = NMS_Agent()
    #agent.start_udp_server()
    agent.start_tcp_server()
