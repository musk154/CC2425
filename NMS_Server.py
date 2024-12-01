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
        Send tasks to an agent and wait for results.
        """
        agent = self.registered_agents.get(agent_id)
        if agent and agent_id in self.tasks:
            try:
                tasks_to_send = self.tasks[agent_id]
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_address = agent["address"]

                # Initialize sequence number tracking for this agent
                if agent_id not in self.sequence_numbers:
                    self.sequence_numbers[agent_id] = 1

                for task in tasks_to_send:
                    # Use and increment the sequence number for this agent
                    seq_number = self.sequence_numbers[agent_id]
                    self.sequence_numbers[agent_id] += 1

                    # Ensure seq_number is within the valid 32-bit unsigned integer range
                    seq_number = seq_number & 0xFFFFFFFF

                    # Encode the task into binary
                    task_binary = json.dumps(task).encode('utf-8')
                    task_length = len(task_binary)
                    
                    # Prepare message with sequence number and task
                    message = struct.pack("!I I", seq_number, task_length) + task_binary

                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            # Send the task
                            print(f"[UDP] Attempting to send task. Destination: {client_address}")
                            print(f"[UDP] Message length: {len(message)} bytes")
                            
                            udp_socket.sendto(message, client_address)
                            print(f"[UDP] Sent task seq {seq_number} to agent {agent_id}")

                            # Wait for acknowledgment
                            udp_socket.settimeout(5.0)
                            try:
                                data, addr = udp_socket.recvfrom(4096)
                                print(f"[UDP] Received data from {addr}")
                                print(f"[UDP] Received data: {data}")
                                
                                # Check if it's an acknowledgment
                                try:
                                    ack_type = data[:4].decode('utf-8').strip('\x00')
                                    print(f"[UDP] ACK Type: {ack_type}")
                                    
                                    if ack_type == "TASK":
                                        ack_seq, = struct.unpack("!I", data[4:8])
                                        if ack_seq == seq_number:
                                            print(f"[UDP] Received task ACK for seq {seq_number}")
                                            break
                                    else:
                                        print(f"[UDP] Received unexpected message type: {ack_type}")
                                except Exception as decode_err:
                                    print(f"[UDP] Error decoding ACK: {decode_err}")
                            
                            except socket.timeout:
                                print(f"[UDP] Timeout waiting for ACK for seq {seq_number}")
                        
                        except Exception as send_err:
                            print(f"[UDP] Error sending task: {send_err}")
                    
                    else:
                        print(f"[UDP] Failed to send task seq {seq_number} after {max_retries} attempts")
                        continue

                udp_socket.close()

            except Exception as e:
                print(f"[UDP] Error in send_task_to_agent: {e}")

    def handle_agent_registration(self, client_address, agent_id):
        """
        Handle registration of an agent and send task count and tasks.
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
                data, client_address = udp_socket.recvfrom(4096)
                print(f"[UDP] Received raw data from {client_address}: {data}")

                try:
                    # Decode the message type (first 4 bytes) and strip null bytes
                    message_type = data[:4].decode('utf-8').strip('\x00')

                    if message_type == "ACK":
                        # Handle agent registration or acknowledgment
                        self.handle_ack(data, client_address)
                    elif message_type == "RES":
                        # Handle task result
                        self.handle_task_result(data[4:], client_address)
                    else:
                        print(f"[UDP] Unknown message type: {message_type}")
                except Exception as e:
                    print(f"[UDP] Error processing data: {e}")
        except Exception as e:
            print(f"[UDP] Server error: {e}")
        finally:
            udp_socket.close()

    def handle_ack(self, data, client_address):
        """
        Handle ACK message from agent.
        """
        try:
            # Decode the agent ID (32 bytes after the 4-byte "ACK")
            agent_id = struct.unpack("4s32s", data[:36])[1].decode('utf-8').strip('\x00')
            print(f"[UDP] Received ACK from agent {agent_id} at {client_address}")

            # Register the agent and assign tasks
            self.handle_agent_registration(client_address, agent_id)
        except Exception as e:
            print(f"[UDP] Error handling ACK: {e}")

    
    def handle_task_result(self, data, client_address):
        """
        Handle task result message from agent.
        """
        try:
            # Check message type
            msg_type = data[:4].decode('utf-8').strip('\x00')
            if msg_type != "TRES":
                print(f"[UDP] Unexpected message type: {msg_type}")
                return

            # Unpack sequence number and decode the JSON result
            seq_number, = struct.unpack("!I", data[4:8])
            result_data = json.loads(data[8:].decode('utf-8'))
            print(f"[UDP] Received task result seq {seq_number} from {client_address}")
            
            # Optionally store results for future use
            self.store_results(client_address, seq_number, result_data)
        except json.JSONDecodeError as e:
            print(f"[UDP] Error decoding JSON: {e}")
        except Exception as e:
            print(f"[UDP] Error handling task result: {e}")



    def store_results(self, client_address, seq_number, result_data):
        """
        Store the received results for later use.
        """
        print(f"Storing results from {client_address}: seq {seq_number} - {result_data}")
        # Implement your storage logic (e.g., save to database or file)


    #Starting the actual server side
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