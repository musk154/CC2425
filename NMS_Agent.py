import socket
import sys
import struct
import json
import time
from metrics_collector import MetricCollector

class NMS_Agent:
    
    
    def __init__(self, server_ip, server_port, agent_id):
        """
        Initialize the agent with the server details and agent ID.

        Args:
            server_ip (str): IP address of the server.
            server_port (int): Port number of the server.
            agent_id (str): Unique identifier for the agent.
        """
        self.server_ip = server_ip  # Server IP address
        self.server_port = server_port  # Server port
        self.agent_id = agent_id  # Agent ID

        # Create a UDP socket for communication
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Enable port reuse to avoid "Address already in use" errors
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the specified local port (12345)
        self.ip = "0.0.0.0"  # Bind to all available interfaces
        self.port = 12345    # Fixed port for sending and receiving
        self.udp_socket.bind((self.ip, self.port))

        # Set a timeout for the socket (e.g., 5 seconds)
        self.udp_socket.settimeout(5)

        print(f"[UDP] Agent bound to {self.ip}:{self.port}")

        # NOTE: Removed the `connect` call to allow receiving packets from any source.

    def send_ack(self):
        """
        Send an initial ACK message to the server for registration.
        """
        message_type = b"ACK"  # 4 bytes
        agent_id = self.agent_id.encode().ljust(32, b'\x00')  # 32-byte agent ID
        message = struct.pack("4s32s", message_type, agent_id)

        try:
            # Send the ACK message to the server's address
            self.udp_socket.sendto(message, (self.server_ip, self.server_port))
            print(f"[UDP] Binary ACK sent to server {self.server_ip}:{self.server_port} from port {self.port}")
        except Exception as e:
            print(f"[UDP] Error sending ACK to server: {e}")

    def receive_tasks(self):
        """
        Continuously receive tasks from the server, process them, and send results back.
        """
        while True:
            print("[UDP] Agent waiting to receive tasks...")
            try:
                # Receive data and the sender's address
                data, addr = self.udp_socket.recvfrom(4096)  # Use recvfrom to get the sender's address
                print(f"[DEBUG] Raw data received from {addr}: {data}")
                print(f"[DEBUG] Data length: {len(data)} bytes")

                # Ensure the packet is large enough to contain at least the sequence number and task length
                if len(data) < 8:
                    print(f"[UDP] Received a non-task message: {data}")
                    continue  # Skip processing this message

                # Decode and process the task
                self.process_task(data, addr)

            except socket.timeout:
                print("[DEBUG] recv timeout, no data received")
            except Exception as e:
                print(f"[UDP] Error in receive_tasks: {e}")

    

    def send_task_ack(self, seq_number, addr):
        """
        Send an ACK message to the server for a received task.
        """
        # Create the ACK message with the sequence number
        ack_message = struct.pack("!4sI", b"TASK", seq_number)
        try:
            # Send the ACK message to the server's address
            self.udp_socket.sendto(ack_message, addr)
            print(f"[UDP] Sent task ACK for seq {seq_number} to {addr}")
        except Exception as e:
            print(f"[UDP] Error sending task ACK: {e}")

    def execute_task(self, task, metric_collector):
        """
        Execute a task received from the server.

        Args:
            task (dict): The task details, as decoded from the server's message.
            metric_collector (MetricCollector): An instance of MetricCollector for simulating task execution.

        Returns:
            dict: The results of the executed task.
        """
        device_id = task.get('device_id')
        device_metrics = task.get('device_metrics', {})
        link_metrics = task.get('link_metrics', {})
        print(f"Executing task for device: {device_id}")

        # Prepare the results dictionary
        results = {
            "device_id": device_id,
            "results": {},
            "status": "success"
        }

        try:
            # Simulate device metrics collection
            if "cpu_usage" in device_metrics and device_metrics["cpu_usage"]:
                results["results"]["cpu_usage"] = metric_collector.collect_cpu_usage()
            if "ram_usage" in device_metrics and device_metrics["ram_usage"]:
                results["results"]["ram_usage"] = metric_collector.collect_ram_usage()
            if "interface_stats" in device_metrics:
                interfaces = device_metrics["interface_stats"]
                results["results"]["interface_stats"] = metric_collector.collect_interface_stats(interfaces)

            # Simulate link metrics collection
            for metric, params in link_metrics.items():
                if metric == "latency":
                    results["results"]["latency"] = metric_collector.ping(
                        destination=params["destination"],
                        packet_count=params["packet_count"]
                    )
                elif metric == "packet_loss":
                    results["results"]["packet_loss"] = metric_collector.iperf(
                        server=params["server_address"],
                        role=params["role"],
                        duration=params["duration"],
                        protocol=params["transport_type"]
                    )

        except Exception as e:
            # Log and include the error in the results
            print(f"[DEBUG] Error executing task: {e}")
            results["status"] = "failure"
            results["error"] = str(e)

        return results

    

    def execute_task_periodically(self, task, seq_number, addr):
        """
        Execute a task periodically based on the frequency passed by the server.

        Args:
            task (dict): The task details.
            seq_number (int): The sequence number of the task.
            addr (tuple): The server address.
        """
        frequency = task.get("frequency")  # Frequency passed by the server
        if frequency is None or not isinstance(frequency, (int, float)) or frequency <= 0:
            print("[DEBUG] Invalid or missing frequency in task. Defaulting to 20 seconds.")
            frequency = 20  # Default to 20 seconds if invalid or missing

        device_id = task.get("device_id")
        metric_collector = MetricCollector()  # Instantiate MetricCollector

        print(f"[UDP] Starting periodic execution for device: {device_id}, frequency: {frequency} seconds")

        try:
            while True:
                # Execute the task
                results = self.execute_task(task, metric_collector)

                # Send the task results back to the server
                self.send_results_to_server(seq_number, results, addr)

                # Wait for the next execution
                print(f"[UDP] Waiting {frequency} seconds before the next execution...")
                time.sleep(frequency)

        except KeyboardInterrupt:
            print(f"[UDP] Stopping periodic execution for device: {device_id}")
        except Exception as e:
            print(f"[DEBUG] Error during periodic execution for {device_id}: {e}")


    def process_task(self, data, addr):
        """
        Process a task received from the server.
        """
        try:
            # Decode the sequence number and task length from the first 8 bytes
            seq_number, task_length = struct.unpack("!I I", data[:8])
            print(f"[DEBUG] Decoded seq_number: {seq_number}, task_length: {task_length}")

            # Extract the task binary data and decode it into a JSON object
            task_binary = data[8:8 + task_length]
            task = json.loads(task_binary.decode('utf-8'))
            print(f"[UDP] Received task seq {seq_number}: {task}")

            # Send task acknowledgment back to the server
            self.send_task_ack(seq_number, addr)

            # Start periodic execution of the task
            self.execute_task_periodically(task, seq_number, addr)

        except struct.error as e:
            print(f"[DEBUG] Struct unpacking error: {e}")
        except json.JSONDecodeError as e:
            print(f"[DEBUG] JSON decoding error: {e}")
        except Exception as e:
            print(f"[DEBUG] Error processing task: {e}")



    def send_results_to_server(self, seq_number, results, addr):
        """
        Send the task results back to the server.

        Args:
            seq_number (int): Sequence number of the task.
            results (dict): Task results to send.
            addr (tuple): Server address (IP, port).
        """
        try:
            result_binary = json.dumps(results).encode('utf-8')
            message = struct.pack("!4sI", b"TRES", seq_number) + result_binary

            # Ensure results are sent to the server's listening port (12345)
            server_address = (self.server_ip, 12345)
            self.udp_socket.sendto(message, server_address)
            print(f"[UDP] Sent task results seq {seq_number} to {server_address}")
        except Exception as e:
            print(f"[UDP] Error sending results to server: {e}")




if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 NMS_Agent.py <server_ip> <agent_id>")
        sys.exit(1)

    server_ip = sys.argv[1]  # First argument: Server IP
    agent_id = sys.argv[2]   # Second argument: Agent ID
    agent = NMS_Agent(server_ip, 12345, agent_id)
    agent.send_ack()
    agent.receive_tasks()
