import socket
import sys
import subprocess
import json
import time
import threading

class MetricCollector:
    def ping(self, destination, packet_count):
        """
        Execute the ping command to measure latency and packet loss.

        Args:
            destination (str): Destination IP address.
            packet_count (int): Number of packets to send.

        Returns:
            dict: Results of the ping command.
        """
        try:
            result = subprocess.run(
                ["ping", "-c", str(packet_count), destination],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                output = result.stdout
                # Parse output to extract metrics
                latency = self._extract_latency(output)
                return {"latency": latency, "status": "success"}
            else:
                return {"error": result.stderr, "status": "failure"}
        except Exception as e:
            return {"error": str(e), "status": "failure"}

    def iperf(self, server, role, duration, protocol):
        """
        Execute the iperf command for bandwidth and jitter analysis.

        Args:
            server (str): Server address.
            role (str): 'client' or 'server'.
            duration (int): Duration of the test in seconds.
            protocol (str): 'TCP' or 'UDP'.

        Returns:
            dict: Results of the iperf command.
        """
        try:
            protocol_flag = "-u" if protocol.upper() == "UDP" else ""
            command = [
                "iperf3",
                "--client" if role == "client" else "--server",
                server,
                "--time", str(duration),
                protocol_flag
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                # Parse output to extract metrics
                return {"output": output, "status": "success"}
            else:
                return {"error": result.stderr, "status": "failure"}
        except Exception as e:
            return {"error": str(e), "status": "failure"}

    def _extract_latency(self, ping_output):
        """
        Extract latency from ping output.

        Args:
            ping_output (str): Raw output from the ping command.

        Returns:
            float: Average latency in ms.
        """
        try:
            for line in ping_output.splitlines():
                if "avg" in line:
                    avg_latency = line.split("/")[4]
                    return float(avg_latency)
        except Exception:
            pass
        return None

class NMS_Agent:
    def __init__(self, ip, port, agent_id, protocol="UDP"):
        """
        Initializes the agent.

        Args:
            ip (str): Server IP address.
            port (int): Server port.
            agent_id (str): Unique identifier for the agent.
            protocol (str): Protocol to use ("UDP" or "TCP").
        """
        self.server_ip = ip
        self.server_port = port
        self.agent_id = agent_id
        self.protocol = protocol.upper()

        if self.protocol not in ["UDP", "TCP"]:
            raise ValueError("Invalid protocol. Choose 'UDP' or 'TCP'.")
        
        
        
    def set_tasks(self, tasks):
        """
        Set the tasks assigned to this agent.

        Args:
            tasks (list): List of tasks.
        """
        self.tasks = tasks

    def start_metric_collection(self):
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
                args=(device_id, metrics, link_metrics, frequency),
                daemon=True
            ).start()

    def _collect_metrics_periodically(self, device_id, metrics, link_metrics, frequency):
        """
        Collect metrics periodically and send results to the server.

        Args:
            device_id (str): Device ID.
            metrics (dict): Device metrics to collect.
            link_metrics (dict): Link metrics to collect.
            frequency (int): Frequency in seconds.
        """
        while True:
            results = {"device_id": device_id, "metrics": {}, "link_metrics": {}}

            # Collect device metrics
            if metrics.get("cpu_usage"):
                results["metrics"]["cpu_usage"] = self._get_cpu_usage()
            if metrics.get("ram_usage"):
                results["metrics"]["ram_usage"] = self._get_ram_usage()

            # Collect link metrics
            for metric, params in link_metrics.items():
                if metric == "latency":
                    results["link_metrics"]["latency"] = self.metric_collector.ping(
                        params["destination"], params["packet_count"]
                    )
                elif metric == "bandwidth":
                    results["link_metrics"]["bandwidth"] = self.metric_collector.iperf(
                        params["server_address"],
                        params["role"],
                        params["duration"],
                        params["transport_type"]
                    )

            # Send metrics to the server
            self._send_metrics_to_server(results)

            time.sleep(frequency)

    def _send_metrics_to_server(self, results):
        """
        Send collected metrics to the server.

        Args:
            results (dict): Metrics to send.
        """
        try:
            message = json.dumps({"type": "METRICS", "data": results})
            if self.protocol == "TCP":
                self._send_tcp_message(message)
            elif self.protocol == "UDP":
                self._send_udp_message(message)
        except Exception as e:
            print(f"[Agent {self.agent_id}] Error sending metrics: {e}")

    def _get_cpu_usage(self):
        """Simulate CPU usage collection."""
        return 30  # Placeholder value

    def _get_ram_usage(self):
        """Simulate RAM usage collection."""
        return 60  # Placeholder value

    def send_ack(self):
        """
        Sends an ACK message to the server.
        """
        ack_message = {
            "type": "ACK",
            "agent_id": self.agent_id
        }

        message = json.dumps(ack_message)

        if self.protocol == "UDP":
            self._send_udp_message(message)
        elif self.protocol == "TCP":
            self._send_tcp_message(message)

    def _send_udp_message(self, message):
        """
        Sends a message using the UDP protocol.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            try:
                udp_socket.sendto(message.encode(), (self.server_ip, self.server_port))
                print(f"[UDP] ACK sent: {message}")

                # Receive the server's response
                response, _ = udp_socket.recvfrom(1024)
                print(f"[UDP] Response received: {response.decode()}")
            except Exception as e:
                print(f"[UDP] Error sending ACK: {e}")

    def _send_tcp_message(self, message):
        """
        Sends a message using the TCP protocol.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            try:
                tcp_socket.connect((self.server_ip, self.server_port))
                print(f"[TCP] Connected to server {self.server_ip}:{self.server_port}")

                # Send the message
                tcp_socket.sendall(message.encode())
                print(f"[TCP] ACK sent: {message}")

                # Receive the server's response
                response = tcp_socket.recv(1024)
                print(f"[TCP] Response received: {response.decode()}")
            except Exception as e:
                print(f"[TCP] Error sending ACK: {e}")
                
                while True:
                    response = tcp_socket.recv(1024).decode()
                    if not response:
                        break
                    print(f"[TCP] Response from server: {response}")
                    response_data = json.loads(response)
                    if response_data.get("type") == "TASKS":
                        print(f"[Agent {self.agent_id}] Tasks received: {response_data['tasks']}")
            except Exception as e:
                print(f"[TCP] Error communicating with server: {e}")

if __name__ == "__main__":
    # Ensure necessary arguments are provided
    if len(sys.argv) < 4:
        print("Usage: python NMS_Agent.py <SERVER_IP> <SERVER_PORT> <AGENT_ID> [<PROTOCOL>]")
        sys.exit(1)

    # Get arguments from command line
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    agent_id = sys.argv[3]
    protocol = sys.argv[4] if len(sys.argv) > 4 else "TCP"  # Default protocol is TCP

    # Initialize the agent
    agent = NMS_Agent(ip=server_ip, port=server_port, agent_id=agent_id, protocol=protocol)

    # Send ACK to the server
    print(f"Agent {agent_id} sending ACK to {server_ip}:{server_port} using {protocol}...")
    agent.send_ack()
