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
        self.tasks = {}  # Ensure this attribute is initialized
        self.task_parser = None  # Optional: parser for task files


    def load_tasks(self, parser):
        """
        Load tasks using the TaskJSONParser and assign them to agents.

        Args:
            parser (TaskJSONParser): Instance of TaskJSONParser.
        """
        try:
            print("Loading tasks from parser...")
            
            # Initialize the tasks dictionary
            self.tasks = {}

            # Use the parser to get devices and assign tasks to agents
            for device in parser.get_devices():
                assigned_to = device.get("assigned_to")
                if assigned_to:
                    if assigned_to not in self.tasks:
                        self.tasks[assigned_to] = []
                    self.tasks[assigned_to].append(device)

            # Debug: Print loaded tasks
            print(f"Tasks loaded successfully: {self.tasks}")
        except Exception as e:
            print(f"Error loading tasks: {e}")


    def send_task_to_agent(self, agent_id):
        """
        Send tasks to a specific agent with sequence numbers and handle retransmissions.

        Args:
            agent_id (str): ID of the agent.
        """
        agent = self.registered_agents.get(agent_id)
        if agent and agent_id in self.tasks:
            try:
                # Prepare tasks with sequence numbers
                tasks_to_send = self.tasks[agent_id]
                seq_number = 1  # Start with sequence number 1

                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_address = agent["address"]

                for task in tasks_to_send:
                    message = {
                        "seq": seq_number,
                        "task": task
                    }
                    data = json.dumps(message).encode()

                    while True:
                        # Send the task
                        udp_socket.sendto(data, client_address)
                        print(f"[UDP] Sent task seq {seq_number} to {agent_id}: {task}")

                        # Wait for acknowledgment
                        udp_socket.settimeout(2.0)  # Timeout for ACK
                        try:
                            ack_data, _ = udp_socket.recvfrom(1024)
                            ack_message = json.loads(ack_data.decode())
                            if ack_message.get("ack") == seq_number:
                                print(f"[UDP] Received ACK for seq {seq_number}")
                                seq_number += 1
                                break
                        except socket.timeout:
                            print(f"[UDP] No ACK for seq {seq_number}, retransmitting...")

            except Exception as e:
                print(f"[UDP] Error sending tasks to {agent_id}: {e}")



    def handle_agent_registration(self, client_address, agent_id):
        try:
            print(f"Agent registration attempt: {agent_id} from {client_address}")
            print(f"Tasks available: {self.tasks}")

            if not agent_id:
                raise ValueError("Agent ID is missing.")

            # Register the agent
            self.registered_agents[agent_id] = {"address": client_address}
            print(f"Registered agents: {self.registered_agents}")

            # Check if tasks exist for the registered agent
            tasks_for_agent = self.tasks.get(agent_id, [])
            print(f"Tasks for agent {agent_id}: {tasks_for_agent}")

            # Send a response to the agent (e.g., task count)
            task_count = len(tasks_for_agent)
            response = struct.pack("I", task_count)  # Send the task count as a 4-byte integer
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.sendto(response, client_address)
            print(f"[UDP] Task count {task_count} sent to agent {agent_id}")
        except Exception as e:
            print(f"Error in handle_agent_registration: {e}")




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
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp_socket.bind((self.ip, self.port))
            print(f"[UDP] Server listening on {self.ip}:{self.port}...")

            while True:
                try:
                    data, client_address = udp_socket.recvfrom(1024)
                    print(f"[UDP] Raw data received: {data} from {client_address}")

                    # Decode binary data
                    message_type, agent_id = struct.unpack("4s32s", data[:36])
                    message_type = message_type.decode().strip('\x00')
                    agent_id = agent_id.decode().strip('\x00')

                    print(f"[UDP] Received message type {message_type} from {agent_id} at {client_address}")

                    if message_type == "ACK":
                        self.handle_agent_registration(client_address, agent_id)
                except Exception as e:
                    print(f"[UDP] Error receiving or handling data: {e}")
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
    task_file = "tarefa01.json"  # Path to the JSON file
    task_parser = TaskJSONParser(task_file)
    
    ip = sys.argv[1]  # IP fornecido pelo usuário
    port = 12345  # Porta fixa para UDP e TCP

    
     # Cria o servidor com o IP fornecido e a porta fixa
    server = NMS_Server(ip, port)
    
    # Load tasks for each agent from the JSON parser
    server.load_tasks(task_parser)    
    server.start_servers()
    
    
    # Verifica se o parâmetro de IP foi passado corretamente
    if len(sys.argv) < 2:
        print("Uso: python servidor.py <IP>")
        sys.exit(1)

    
    print("Waiting for agent registrations...")
    # Example: Assign tasks to registered agents
    for agent_id, agent_info in server.registered_agents.items():
        tasks = task_parser.get_tasks_for_agent(agent_id)
        for task in tasks:
            server.send_task_to_agent(agent_id, task)