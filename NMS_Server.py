import socket
import threading
import subprocess
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
        self.iperf3_process = None  # Track the iperf3 server process


    def start_iperf3_server(self):
        """
        Start the iperf3 server in the background with support for UDP.
        """
        try:
            print("[iperf3] Starting iperf3 server with UDP support...")
            self.iperf3_process = subprocess.Popen(
                ["iperf3", "--server"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("[iperf3] iperf3 server started successfully with UDP support.")
        except FileNotFoundError:
            print("[iperf3] Error: iperf3 is not installed or not in PATH.")
        except Exception as e:
            print(f"[iperf3] Failed to start iperf3 server: {e}")


    def stop_iperf3_server(self):
        """
        Stop the iperf3 server if it's running.
        """
        if self.iperf3_process and self.iperf3_process.poll() is None:
            print("[iperf3] Stopping iperf3 server...")
            try:
                self.iperf3_process.terminate()
                self.iperf3_process.wait()
                print("[iperf3] iperf3 server stopped successfully.")
            except Exception as e:
                print(f"[iperf3] Failed to stop iperf3 server: {e}")
        else:
            print("[iperf3] iperf3 server is not running.")
    
    
    
    def load_tasks(self, parser):
        """
        Load tasks using the TaskJSONParser and assign them to agents,
        dynamically replacing the server_address and destination with the server's IP.
        """
        try:
            print("Loading tasks from parser...")
            self.tasks = {}
            self.global_frequency = parser.global_frequency

            for device in parser.get_devices():
                # Update server_address and destination dynamically
                
                link_metrics = device.get("link_metrics", {})
                for metric_name, metric in link_metrics.items():
                    if isinstance(metric, dict):
                        if "server_address" in metric:
                            metric["server_address"] = self.ip  # Replace server_address with the server's IP
                        if "destination" in metric:
                            metric["destination"] = self.ip  # Replace destination with the server's IP

                # Assign tasks to agents
                assigned_to = device.get("assigned_to")
                if assigned_to:
                    if assigned_to not in self.tasks:
                        self.tasks[assigned_to] = []
                    self.tasks[assigned_to].append(device)

            print(f"Tasks loaded successfully: {self.tasks}")
        except Exception as e:
            print(f"Error loading tasks: {e}")


    
                

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
        Start the UDP server to handle agent registrations and communication.
        """
        # Start the iperf3 server
        self.start_iperf3_server()
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp_socket.bind((self.ip, self.port))  # Bind to port 12345
            print(f"[UDP] Server listening on {self.ip}:{self.port}...")

            while True:
                data, client_address = self.udp_socket.recvfrom(4096)
                

                try:
                    # Decode the message type
                    message_type = data[:4].decode('utf-8').strip('\x00')
                    print(f"[DEBUG] Message type: {message_type}")
                    if message_type == "ACK":
                        self.handle_ack(data, client_address)
                    elif message_type == "TASK":
                        seq_number, = struct.unpack("!I", data[4:8])
                        print(f"[UDP] Received task ACK for seq {seq_number}")
                    elif message_type == "TRES":
                        self.handle_task_results(data, client_address)
                    else:
                        print(f"[UDP] Unknown message type: {message_type}")
                except Exception as e:
                    print(f"[UDP] Error processing data: {e}")
        except Exception as e:
            print(f"[UDP] Server error: {e}")
        finally:
            self.udp_socket.close()
            
    def start_tcp_server(self):
        """
        Start a TCP server to handle alerts from agents.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.bind((self.ip, self.port))
            tcp_socket.listen(5)  # Allow up to 5 simultaneous connections
            print(f"[TCP] Server listening for alerts on {self.ip}:{self.port}...")

            while True:
                conn, addr = tcp_socket.accept()
                print(f"[TCP] Connection established with {addr}")
                threading.Thread(target=self.handle_alert, args=(conn, addr), daemon=True).start()


    def send_task_to_agent(self, agent_id):
        """
        Send tasks to an agent and include the global frequency.
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

                    # Add global frequency to the task if not already defined
                    task["frequency"] = task.get("frequency", self.global_frequency)

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
                            print(f"[DEBUG] Task being sent to {agent_id} (frequency: {task['frequency']}): {task}")
                            
                            udp_socket.sendto(message, client_address)

                            # Wait for acknowledgment
                            udp_socket.settimeout(5.0)
                            data, addr = udp_socket.recvfrom(4096)
                            print(f"[UDP] Received data from {addr}: {data}")

                            # Check if it's an acknowledgment
                            ack_type = data[:4].decode('utf-8').strip('\x00')
                            if ack_type == "TASK":
                                ack_seq, = struct.unpack("!I", data[4:8])
                                if ack_seq == seq_number:
                                    print(f"[UDP] Received task ACK for seq {seq_number}")
                                    break
                            else:
                                print(f"[UDP] Unexpected message type: {ack_type}")
                        
                        except socket.timeout:
                            print(f"[UDP] Timeout waiting for ACK for seq {seq_number}")
                        
                    else:
                        print(f"[UDP] Failed to send task seq {seq_number} after {max_retries} attempts")
                        continue

                udp_socket.close()

            except Exception as e:
                print(f"[UDP] Error in send_task_to_agent: {e}")




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
 
    
    def handle_task_results(self, data, addr):
        """
        Handle task results received from an agent.

        Args:
            data (bytes): The raw data received from the agent.
            addr (tuple): The address of the agent.
        """
        try:
            # Parse the received message
            header, seq_number = struct.unpack("!4sI", data[:8])
            if header != b"TRES":
                print(f"[UDP] Invalid header received from {addr}: {header}")
                return

            # The rest is the formatted task results
            formatted_results = data[8:].decode('utf-8')
            print(f"[UDP] Received task results seq {seq_number} from {addr}:\n{formatted_results}")

            # Send an acknowledgment (ACK) back to the agent
            ack_message = struct.pack("!4sI", b"TACK", seq_number)
            self.udp_socket.sendto(ack_message, addr)
            print(f"[UDP] Sent ACK for seq {seq_number} to {addr}")

        except Exception as e:
            print(f"[UDP] Error handling task results from {addr}: {e}")

    

    def store_results(self, client_address, seq_number, result_data):
        """
        Store the received results for later use.

        Args:
            client_address (tuple): Address of the agent that sent the result.
            seq_number (int): The sequence number of the task.
            result_data (dict): The results of the task execution.
        """
        
        # Implement storage logic (e.g., save to a file, database, etc.)
    def handle_alert(self, conn, addr):
        """
        Handle an incoming alert from an agent.

        Args:
            conn: The TCP connection object.
            addr: Address of the agent sending the alert.
        """
        try:
            alert_data = conn.recv(4096).decode('utf-8')
            alert_message = json.loads(alert_data)
            print(f"[TCP] Received alert from {alert_message['agent_id']} at {addr}:")
            for metric in alert_message['exceeded_metrics']:
                print(f"  - {metric}")
        except Exception as e:
            print(f"[TCP] Error handling alert from {addr}: {e}")


    #Starting the actual server side
    def start_servers(self):
        
        udp_thread = threading.Thread(target=self.start_udp_server, daemon=True)
        tcp_thread = threading.Thread(target=self.start_tcp_server, daemon=True)
        udp_thread.start()
        tcp_thread.start()
        udp_thread.join()
        tcp_thread.join()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python NMS_Server.py <IP>")
        sys.exit(1)

    ip = sys.argv[1]
    port = 12345

    server = NMS_Server(ip, port)
    server.load_tasks(TaskJSONParser("tarefa01.json"))
    server.start_servers()

    