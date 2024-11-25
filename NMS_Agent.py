import socket
import sys
import struct
import time
import threading
from metrics_collector import MetricCollector



class NMS_Agent:
    def __init__(self, ip, port, agent_id, protocol="UDP"):
        """
        Initializes the agent.

        Args:
            ip (str): Server IP address.
            port (int): Server port.
            agent_id (str): Unique identifier for the agent.
            protocol (str): Protocol to use ("UDP").
        """
        self.server_ip = ip
        self.server_port = port
        self.agent_id = agent_id
        self.protocol = protocol.upper()

        if self.protocol != "UDP":
            raise ValueError("Only UDP protocol is supported in this implementation.")

        self.tasks = []  # Tasks assigned to the agent


    def send_ack(self):
        """
        Sends an ACK message to the server and waits for a task response.
        """
        message_type = b"ACK"  # Fixed size, 4 bytes
        agent_id = self.agent_id.encode().ljust(32, b'\x00')  # 32-byte agent ID

        message = struct.pack("4s32s", message_type, agent_id)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            try:
                udp_socket.sendto(message, (self.server_ip, self.server_port))
                print(f"[UDP] Binary ACK sent to server.")

                udp_socket.settimeout(5.0)  # Set a timeout for receiving
                response, _ = udp_socket.recvfrom(4096)

                # Decode binary response
                task_count = struct.unpack("I", response[:4])[0]  # Assuming the first 4 bytes are the task count
                print(f"[UDP] Received task count from server: {task_count}")
            except socket.timeout:
                print("[UDP] No response from server. Retrying...")
            except Exception as e:
                print(f"[UDP] Error communicating with server: {e}")

    def set_tasks(self, tasks):
        """
        Set the tasks assigned to this agent.

        Args:
            tasks (list): List of tasks.
        """
        self.tasks = tasks

    def start_metric_collection(self, udp_socket):
        """
        Start periodic metric collection for assigned tasks.
        """
        for task in self.tasks:
            device_id = task["device_id"]
            metrics = task["device_metrics"]
            link_metrics = task.get("link_metrics", {})
            frequency = task.get("frequency", 20)

            threading.Thread(
                target=self._collect_metrics_periodically,
                args=(device_id, metrics, link_metrics, frequency, udp_socket),
                daemon=True
            ).start()

    def _collect_metrics_periodically(self, device_id, metrics, link_metrics, frequency, udp_socket):
        """
        Collect metrics periodically and send results to the server.

        Args:
            device_id (str): Device ID.
            metrics (dict): Device metrics to collect.
            link_metrics (dict): Link metrics to collect.
            frequency (int): Frequency in seconds.
            udp_socket (socket): UDP socket for communication.
        """
        while True:
            results = {"device_id": device_id, "metrics": {}, "link_metrics": {}, "agent_id": self.agent_id}

            # Collect device metrics
            if metrics.get("cpu_usage"):
                results["metrics"]["cpu_usage"] = self._get_cpu_usage()
            if metrics.get("ram_usage"):
                results["metrics"]["ram_usage"] = self._get_ram_usage()

            # Collect link metrics
            for metric, params in link_metrics.items():
                if metric == "latency":
                    results["link_metrics"]["latency"] = self._simulate_latency(params["destination"])
                elif metric == "bandwidth":
                    results["link_metrics"]["bandwidth"] = self._simulate_bandwidth(params)

            # Send metrics to the server
            self._send_metrics_to_server(results, udp_socket)
            time.sleep(frequency)

    
    def _send_metrics_to_server(self, results, udp_socket):
        """
        Send collected metrics to the server.

        Args:
            results (dict): Metrics to send.
            udp_socket (socket): UDP socket for communication.
        """
        try:
            # Assume metrics dictionary contains "cpu_usage" and "ram_usage"
            cpu_usage = results["metrics"].get("cpu_usage", 0)
            ram_usage = results["metrics"].get("ram_usage", 0)

            message = struct.pack("4sff", b"METR", cpu_usage, ram_usage)
            udp_socket.sendto(message, (self.server_ip, self.server_port))
            print(f"[UDP] Binary metrics sent to server: CPU={cpu_usage}, RAM={ram_usage}")
        except Exception as e:
            print(f"[UDP] Error sending metrics: {e}")


    def _get_cpu_usage(self):
        """Simulate CPU usage collection."""
        return 30  # Placeholder value

    def _get_ram_usage(self):
        """Simulate RAM usage collection."""
        return 60  # Placeholder value

    def _simulate_latency(self, destination):
        """Simulate latency measurement (placeholder)."""
        return {"latency": 10}  # Simulated value

    def _simulate_bandwidth(self, params):
        """Simulate bandwidth measurement (placeholder)."""
        return {"bandwidth": 100}  # Simulated value


if __name__ == "__main__":
    # Ensure necessary arguments are provided
    if len(sys.argv) < 4:
        print("Usage: python NMS_Agent.py <SERVER_IP> <SERVER_PORT> <AGENT_ID>")
        sys.exit(1)

    # Get arguments from command line
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    agent_id = sys.argv[3]

    # Initialize the agent
    agent = NMS_Agent(ip=server_ip, port=server_port, agent_id=agent_id)

    # Send ACK to the server and wait for tasks
    print(f"Agent {agent_id} starting and sending ACK to {server_ip}:{server_port}...")
    agent.send_ack()