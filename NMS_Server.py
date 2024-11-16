import socket
import threading
import sys
import json

class TaskJSONParser:
    def __init__(self, file_path):
        """
        Initialize the parser and load the JSON file.
        :param file_path: Path to the JSON file.
        """
        self.file_path = file_path
        self.data = self._load_json()

    def _load_json(self):
        """
        Load JSON data from the file.
        :return: Parsed JSON data as a Python object.
        """
        try:
            with open(self.file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {self.file_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")

    def get_task_id(self):
        """Get the task ID."""
        return self.data.get("task", {}).get("task_id")

    def get_devices(self):
        """Get the list of devices."""
        return self.data.get("task", {}).get("devices", [])

    def get_device_metrics(self, device_id):
        """
        Get metrics for a specific device.
        :param device_id: The ID of the device.
        :return: Metrics of the device or None if not found.
        """
        devices = self.get_devices()
        for device in devices:
            if device.get("device_id") == device_id:
                return device.get("device_metrics")
        return None

    def update_device_alert_conditions(self, device_id, new_conditions):
        """
        Update alert flow conditions for a specific device.
        :param device_id: The ID of the device.
        :param new_conditions: A dictionary with new alert flow conditions.
        """
        devices = self.get_devices()
        for device in devices:
            if device.get("device_id") == device_id:
                if "link_metrics" in device and "alertflow_conditions" in device["link_metrics"]:
                    device["link_metrics"]["alertflow_conditions"].update(new_conditions)

    def save(self, output_file=None):
        """
        Save the updated JSON to a file.
        :param output_file: The file to save the data. If None, overwrites the original file.
        """
        save_path = output_file or self.file_path
        with open(save_path, 'w') as file:
            json.dump(self.data, file, indent=4)

class NMS_Server:
    def __init__(self, ip, port=12345):
        """
        Inicializa o servidor.

        Args:
            ip (str): Endereço IP do servidor.
            port (int): Porta do servidor (fixa).
        """
        self.ip = ip
        self.port = port

    def start_udp_server(self):
        """
        Inicia o servidor UDP.
        """
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp_socket.bind((self.ip, self.port))
            print(f"[UDP] Servidor escutando em {self.ip}:{self.port}...")

            while True:
                data, client_address = udp_socket.recvfrom(1024)
                print(f"[UDP] Recebido de {client_address}: {data.decode()}")

                response = "Mensagem recebida (UDP)!"
                udp_socket.sendto(response.encode(), client_address)
                print(f"[UDP] Resposta enviada para {client_address}")
        except Exception as e:
            print(f"[UDP] Erro no servidor: {e}")
        finally:
            udp_socket.close()
            print("[UDP] Servidor encerrado.")

    def handle_tcp_client(self, client_socket, client_address):
        """
        Lida com um cliente TCP.
        """
        try:
            data = client_socket.recv(1024)
            print(f"[TCP] Recebido de {client_address}: {data.decode()}")

            response = "Mensagem recebida (TCP)!"
            client_socket.send(response.encode())
            print(f"[TCP] Resposta enviada para {client_address}")
        except Exception as e:
            print(f"[TCP] Erro ao lidar com o cliente {client_address}: {e}")
        finally:
            client_socket.close()
            print(f"[TCP] Conexão com {client_address} encerrada.")

    def start_tcp_server(self):
        """
        Inicia o servidor TCP.
        """
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp_socket.bind((self.ip, self.port))
            tcp_socket.listen(5)
            print(f"[TCP] Servidor escutando em {self.ip}:{self.port}...")

            while True:
                client_socket, client_address = tcp_socket.accept()
                print(f"[TCP] Conexão estabelecida com {client_address}")

                # Cria uma thread para lidar com cada cliente
                threading.Thread(target=self.handle_tcp_client, args=(client_socket, client_address), daemon=True).start()
        except Exception as e:
            print(f"[TCP] Erro no servidor: {e}")
        finally:
            tcp_socket.close()
            print("[TCP] Servidor encerrado.")

    def start_servers(self):
        """
        Inicia ambos os servidores UDP e TCP em threads separadas.
        """
        # Cria e inicia a thread do servidor UDP
        udp_thread = threading.Thread(target=self.start_udp_server, daemon=True)
        udp_thread.start()

        # Cria e inicia a thread do servidor TCP
        tcp_thread = threading.Thread(target=self.start_tcp_server, daemon=True)
        tcp_thread.start()

        # Aguarda as threads de ambos os servidores
        udp_thread.join()
        tcp_thread.join()

if __name__ == "__main__":
    #parse no ficheiro json
    
    parser = TaskJSONParser("tarefa01.json")
    task_id = parser.get_task_id()
    print("Task ID:", task_id)
    
    # Verifica se o parâmetro de IP foi passado corretamente
    if len(sys.argv) < 2:
        print("Uso: python servidor.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]  # IP fornecido pelo usuário
    port = 12345  # Porta fixa para UDP e TCP

    # Cria o servidor com o IP fornecido e a porta fixa
    server = NMS_Server(ip, port)
    server.start_servers()