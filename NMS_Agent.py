import socket
import sys

class NMS_Agent:
    def __init__(self, ip, port, protocol="UDP"):
        """
        Inicializa o agente.

        Args:
            ip (str): Endereço IP do servidor.
            port (int): Porta do servidor.
            protocol (str): Protocolo a ser usado ("UDP" ou "TCP").
        """
        self.server_ip = ip
        self.server_port = port
        self.protocol = protocol.upper()

        if self.protocol not in ["UDP", "TCP"]:
            raise ValueError("Protocolo inválido. Escolha 'UDP' ou 'TCP'.")

    def send_message(self, message):
        """
        Envia uma mensagem ao servidor.

        Args:
            message (str): Mensagem a ser enviada.
        """
        if self.protocol == "UDP":
            self._send_udp_message(message)
        elif self.protocol == "TCP":
            self._send_tcp_message(message)

    def _send_udp_message(self, message):
        """
        Envia uma mensagem usando o protocolo UDP.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            try:
                udp_socket.sendto(message.encode(), (self.server_ip, self.server_port))
                print(f"[UDP] Mensagem enviada: {message}")

                # Recebe a resposta do servidor
                response, _ = udp_socket.recvfrom(1024)
                print(f"[UDP] Resposta recebida: {response.decode()}")
            except Exception as e:
                print(f"[UDP] Erro ao enviar mensagem: {e}")

    def _send_tcp_message(self, message):
        """
        Envia uma mensagem usando o protocolo TCP.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            try:
                tcp_socket.connect((self.server_ip, self.server_port))
                print(f"[TCP] Conectado ao servidor {self.server_ip}:{self.server_port}")

                # Envia a mensagem
                tcp_socket.sendall(message.encode())
                print(f"[TCP] Mensagem enviada: {message}")

                # Recebe a resposta do servidor
                response = tcp_socket.recv(1024)
                print(f"[TCP] Resposta recebida: {response.decode()}")
            except Exception as e:
                print(f"[TCP] Erro ao enviar mensagem: {e}")


if __name__ == "__main__":
    # Verifica se os argumentos necessários foram fornecidos
    if len(sys.argv) < 4:
        print("Uso: python agente.py <IP_SERVIDOR> <PORTA_SERVIDOR> <PROTOCOLO>")
        sys.exit(1)

    # Obtém os argumentos da linha de comando
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    protocol = sys.argv[3]  # "UDP" ou "TCP"

    # Instancia o agente
    agent = NMS_Agent(ip=server_ip, port=server_port, protocol=protocol)

    # Mensagem a ser enviada
    while True:
        message = input(f"Digite uma mensagem para o servidor ({protocol}): ")
        if message.lower() == "exit":
            print("Encerrando o agente.")
            break
        agent.send_message(message)
