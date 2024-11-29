import socket
import sys
import struct
import json
import time
import threading

class NMS_Agent:
    def __init__(self, ip, port, agent_id):
        self.server_ip = ip
        self.server_port = port
        self.agent_id = agent_id
        self.sequence_number = 1
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_ack(self):
        """
        Send ACK message to server and wait for tasks.
        """
        message_type = b"ACK"
        agent_id = self.agent_id.encode().ljust(32, b'\x00')
        message = struct.pack("4s32s", message_type, agent_id)

        try:
            self.udp_socket.sendto(message, (self.server_ip, self.server_port))
            print(f"[UDP] Binary ACK sent to server.")

            # Set timeout and receive task count
            self.udp_socket.settimeout(5.0)
            response, _ = self.udp_socket.recvfrom(4)
            
            # Correctly unpack task count as unsigned 32-bit integer
            task_count = struct.unpack("!I", response)[0]
            print(f"[UDP] Received task count from server: {task_count}")

            # Start receiving tasks
            self.receive_tasks()

        except socket.timeout:
            print("[UDP] No response from server. Retrying...")
        except Exception as e:
            print(f"[UDP] Error communicating with server: {e}")

    def receive_tasks(self):
        """
        Receive and process tasks from server.
        """
        try:
            while True:
                # Receive task details
                data, server_address = self.udp_socket.recvfrom(4096)
                
                # Unpack sequence number and task length
                seq_number, task_length = struct.unpack("!II", data[:8])
                task_binary = data[8:8 + task_length]
                
                # Decode task from JSON
                task = json.loads(task_binary.decode('utf-8'))
                print(f"[UDP] Received task seq {seq_number}: {task}")

                # Send ACK for the received task
                ack_message = struct.pack("!I", seq_number)
                self.udp_socket.sendto(ack_message, server_address)
                print(f"[UDP] Sent ACK for seq {seq_number}")

                # Optional: Process the task
                self.process_task(task)

        except Exception as e:
            print(f"[UDP] Error receiving tasks: {e}")

    def process_task(self, task):
        """
        Process the received task.
        """
        device_id = task.get('device_id')
        device_metrics = task.get('device_metrics', {})
        link_metrics = task.get('link_metrics', {})

        print(f"Processing task for device: {device_id}")
        print("Device Metrics:", device_metrics)
        print("Link Metrics:", link_metrics)

if __name__ == "__main__":
    # Validate command-line arguments
    if len(sys.argv) < 4:
        print("Usage: python NMS_Agent.py <SERVER_IP> <SERVER_PORT> <AGENT_ID>")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    agent_id = sys.argv[3]

    # Initialize and start the agent
    agent = NMS_Agent(ip=server_ip, port=server_port, agent_id=agent_id)
    agent.send_ack()