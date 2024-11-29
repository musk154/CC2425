import socket
import threading
import sys
import struct
import json
from task_parser import TaskJSONParser

class NMS_Server:
    def __init__(self, ip, port=12345):
        self.ip = ip
        self.port = port
        self.registered_agents = {}
        self.tasks = {}
        self.sequence_numbers = {}  # Track sequence numbers per agent

    def load_tasks(self, parser):
        """
        Load tasks using the TaskJSONParser and assign them to agents.
        """
        try:
            print("Loading tasks from parser...")
            self.tasks = {}

            for device in parser.get_devices():
                assigned_to = device.get("assigned_to")
                if assigned_to:
                    if assigned_to not in self.tasks:
                        self.tasks[assigned_to] = []
                    self.tasks[assigned_to].append(device)

            print(f"Tasks loaded successfully: {self.tasks}")
        except Exception as e:
            print(f"Error loading tasks: {e}")

    def send_task_to_agent(self, agent_id):
        """
        Send tasks to a specific agent with robust sequence numbering and ACK handling.
        """
        agent = self.registered_agents.get(agent_id)
        if agent and agent_id in self.tasks:
            try:
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_address = agent["address"]
                
                # Initialize sequence number for this agent if not exists
                if agent_id not in self.sequence_numbers:
                    self.sequence_numbers[agent_id] = 1

                for task in self.tasks[agent_id]:
                    seq_number = self.sequence_numbers[agent_id]
                    
                    # Convert task to JSON string for consistent encoding
                    task_json = json.dumps(task)
                    task_binary = task_json.encode('utf-8')
                    task_length = len(task_binary)

                    # Pack sequence number and task length
                    message = struct.pack("!II", seq_number, task_length) + task_binary

                    max_retries = 3
                    for attempt in range(max_retries):
                        udp_socket.sendto(message, client_address)
                        print(f"[UDP] Sent task seq {seq_number} to agent {agent_id}")

                        # Wait for acknowledgment
                        udp_socket.settimeout(2.0)
                        try:
                            ack_data, _ = udp_socket.recvfrom(1024)
                            ack_seq = struct.unpack("!I", ack_data)[0]
                            
                            if ack_seq == seq_number:
                                print(f"[UDP] Received ACK for seq {seq_number}")
                                self.sequence_numbers[agent_id] += 1  # Increment sequence
                                break
                        except socket.timeout:
                            print(f"[UDP] No ACK for seq {seq_number}, retry {attempt+1}")
                            if attempt == max_retries - 1:
                                print(f"[UDP] Max retries reached for seq {seq_number}")
            except Exception as e:
                print(f"[UDP] Error sending tasks to {agent_id}: {e}")

    def handle_agent_registration(self, client_address, agent_id):
        """
        Handle registration of an agent and send task count.
        """
        try:
            print(f"Agent registration: {agent_id} from {client_address}")

            # Register the agent
            self.registered_agents[agent_id] = {"address": client_address}
            
            # Get tasks for the agent
            tasks_for_agent = self.tasks.get(agent_id, [])
            task_count = len(tasks_for_agent)

            # Create UDP socket to send response
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Pack task count as a 32-bit unsigned integer
            response = struct.pack("!I", task_count)
            udp_socket.sendto(response, client_address)
            
            print(f"[UDP] Task count {task_count} sent to agent {agent_id}")

            # Send the actual tasks to the agent
            self.send_task_to_agent(agent_id)

        except Exception as e:
            print(f"Error in handle_agent_registration: {e}")

    def start_udp_server(self):
        """
        Start UDP server to handle agent registrations and communication.
        """
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp_socket.bind((self.ip, self.port))
            print(f"[UDP] Server listening on {self.ip}:{self.port}...")

            while True:
                data, client_address = udp_socket.recvfrom(1024)
                print(f"[UDP] Received data from {client_address}")

                # Unpack message type and agent ID
                message_type, agent_id = struct.unpack("4s32s", data[:36])
                message_type = message_type.decode().strip('\x00')
                agent_id = agent_id.decode().strip('\x00')

                if message_type == "ACK":
                    self.handle_agent_registration(client_address, agent_id)

        except Exception as e:
            print(f"[UDP] Server error: {e}")
        finally:
            udp_socket.close()

    def start_servers(self):
        """
        Start UDP server in a separate thread.
        """
        udp_thread = threading.Thread(target=self.start_udp_server, daemon=True)
        udp_thread.start()
        udp_thread.join()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python NMS_Server.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]
    port = 12345

    server = NMS_Server(ip, port)
    server.load_tasks(TaskJSONParser("tarefa01.json"))
    server.start_servers()