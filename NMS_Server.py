import socket
import threading
import sys
from task_parser import TaskJSONParser
import json
import struct

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
        self.registered_agents = {} # Dicionário para armazenar os agentes registrados

    def load_tasks(self, parser):
        """
        Load tasks for each agent from the JSON parser.
        """
        for device in parser.get_devices():
            agent_id = device.get("assigned_to")
            if agent_id:
                if agent_id not in self.tasks:
                    self.tasks[agent_id] = []
                self.tasks[agent_id].append(device)
                
    def send_task_to_agent(self, agent_id):
        """
        Send tasks to a specific agent.

        Args:
            agent_id (str): ID of the agent.
        """
        agent = self.registered_agents.get(agent_id)
        if agent and agent_id in self.tasks:
            try:
                tasks = self.tasks[agent_id]
                message = json.dumps({"type": "TASKS", "tasks": tasks})

                # Send the tasks via the appropriate protocol
                if "socket" in agent:
                    agent["socket"].send(message.encode())
                    print(f"Tasks sent to {agent_id}")
                else:
                    print(f"Cannot send tasks to {agent_id}: Socket not found.")
            except Exception as e:
                print(f"Error sending tasks to {agent_id}: {e}")
        else:
            print(f"No tasks or agent found for {agent_id}.")

    def handle_agent_registration(self, client_address, agent_id):
        """
        Handle registration of an agent.
        Args:
            client_address (tuple): Address of the agent.
            agent_id (str): Unique identifier for the agent.
        """
        try:
            # Register the agent
            self.registered_agents[agent_id] = {"address": client_address}
            print(f"Agent {agent_id} registered from {client_address}")

            # Send confirmation back to the agent
            tasks = [{"task_id": 1}, {"task_id": 2}, {"task_id": 3}]  # Example tasks
            task_message = struct.pack("I", len(tasks))  # Pack number of tasks
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.sendto(task_message, client_address)
            print(f"Tasks sent to agent {agent_id}: {tasks}")
        except Exception as e:
            print(f"Error handling registration for {agent_id} from {client_address}: {e}")




    def handle_tcp_client(self, client_socket, client_address):
        try:
            data = client_socket.recv(1024).decode()
            print(f"[TCP] Received from {client_address}: {data}")
            self.handle_agent_registration(client_socket, client_address, data)
        except Exception as e:
            print(f"[TCP] Error handling client {client_address}: {e}")
        finally:
            client_socket.close()

    def handle_metrics(self, agent_id, metrics):
        """
        Handle incoming metrics from an agent.

        Args:
            agent_id (str): ID of the agent.
            metrics (dict): Metrics data.
        """
        print(f"[Server] Metrics received from {agent_id}: {metrics}")
        
    

    def start_udp_server(self):
        """
        Start the UDP server to handle incoming messages.
        """
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp_socket.bind((self.ip, self.port))
            print(f"[UDP] Server listening on {self.ip}:{self.port}...")

            while True:
                data, client_address = udp_socket.recvfrom(1024)

                # Decode binary data
                message_type, agent_id = struct.unpack("4s32s", data[:36])
                message_type = message_type.decode().strip('\x00')
                agent_id = agent_id.decode().strip('\x00')

                print(f"[UDP] Received message type {message_type} from {agent_id} at {client_address}")

                if message_type == "ACK":
                    self.handle_agent_registration(client_address, agent_id)
        except Exception as e:
            print(f"[UDP] Server error: {e}")
        finally:
            udp_socket.close()
            print("[UDP] Server closed.")


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
    
    # Load tasks for each agent from the JSON parser
    server.load_tasks(parser)
    
    print("Waiting for agent registrations...")
    # Example: Assign tasks to registered agents
    for agent_id, agent_info in server.registered_agents.items():
        tasks = parser.get_tasks_for_agent(agent_id)
        for task in tasks:
            server.send_task_to_agent(agent_id, task)