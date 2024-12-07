import socket
import sys
import struct
import json
import time
import datetime
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
        self.alert_counts = {}
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
            metric_collector (MetricCollector): An instance of MetricCollector for task execution.

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

        # Initialize a cache for iperf results to avoid multiple executions
        iperf_results_cache = None

        try:
            # Collect device metrics selectively
            if "cpu_usage" in device_metrics and device_metrics["cpu_usage"]:
                results["results"]["cpu_usage"] = metric_collector.collect_cpu_usage()
            if "ram_usage" in device_metrics and device_metrics["ram_usage"]:
                results["results"]["ram_usage"] = metric_collector.collect_ram_usage()
            if "interface_stats" in device_metrics:
                interfaces = device_metrics["interface_stats"]
                results["results"]["interface_stats"] = metric_collector.collect_interface_stats(interfaces)

            # Collect link metrics selectively
            for metric, params in link_metrics.items():
                # Latency
                if "latency" in link_metrics:
                    try:
                        # Run ping for latency
                        latency_params = link_metrics["latency"]
                        latency_result = metric_collector.ping(
                            destination=latency_params["destination"],
                            packet_count=latency_params["packet_count"]
                        )
                        results["results"]["latency"] = latency_result  # Store the full result
                    except Exception as e:
                        print(f"[DEBUG] Error collecting latency: {e}")
                        results["results"]["latency"] = {
                            "status": "failure",
                            "error": str(e)
                        }
                else:
                    print("[DEBUG] Latency metric not required for this task.")

                

                # Run iperf and store the results under "iperf" key
                if metric in ["packet_loss", "bandwidth", "jitter"]:
                    try:
                        # Ensure params is properly initialized and protocol is assigned
                        protocol = params.get("transport_type", "UDP").lower()
                        port = params.get("port")
                        if not iperf_results_cache:
                            
                            print(f"[DEBUG] Running iperf for link metrics with protocol: {protocol}...")
                            iperf_results = metric_collector.iperf(
                                server=params["server_address"],
                                role=params["role"],
                                duration=params["duration"],
                                protocol=protocol,
                                port = port
                                
                            )
                            print(f"[DEBUG] Iperf results: {iperf_results}")
                            if iperf_results.get("status") == "success":
                                # Cache the full iperf results for this task execution
                                iperf_results_cache = iperf_results.get("results", {})
                                # Store the full iperf results in the results dictionary
                                results["results"]["iperf"] = iperf_results  # Add the entire iperf dictionary
                            else:
                                results["results"]["iperf"] = {
                                    "status": "failure",
                                    "error": iperf_results.get("error", "Unknown error")
                                }
                                continue

                        # Use cached iperf results for the current metric
                        if iperf_results_cache:
                            results["results"][metric] = iperf_results_cache.get(metric, "N/A")

                    except KeyError as e:
                        print(f"[DEBUG] Missing key in task parameters: {e}")
                        results["results"]["iperf"] = {
                            "status": "failure",
                            "error": f"Missing parameter: {e}"
                        }
        except Exception as e:
            print(f"[DEBUG] Error executing iperf for {metric}: {e}")
            results["results"]["iperf"] = {
                "status": "failure",
                "error": str(e)
            }


        return results

    def execute_task_periodically(self, task, seq_number, addr, frequency):
        """
        Periodically execute a task based on the given frequency.

        Args:
            task (dict): The task details.
            seq_number (int): The sequence number received from the server.
            addr (tuple): The server's address (IP, port).
            frequency (int): The frequency (in seconds) at which to execute the task.
        """
        device_id = task.get("device_id")
        metric_collector = MetricCollector()
        link_metrics = task.get("link_metrics", {})
        alertflow_conditions = task.get("link_metrics", {}).get("alertflow_conditions", {})

        print(f"[UDP] Starting periodic execution for device: {device_id}, frequency: {frequency} seconds")

        try:
            while True:
                # Check if alert threshold is reached
                if self.alert_counts.get(device_id, 0) >= 2:
                    print(f"[DEBUG] Alert threshold reached for {device_id}. Stopping task execution.")
                    break

                # Execute the task
                results = self.execute_task(task, metric_collector)

                # Send the results to the server with the current sequence number
                self.send_results_to_server(seq_number, results, addr, link_metrics)

                # Check alert conditions and send alerts if needed
                exceeded_metrics = self.check_alert_conditions(results, alertflow_conditions)
                if exceeded_metrics:
                    self.send_alert_to_server(exceeded_metrics, device_id)

                # Increment the sequence number for the next iteration
                seq_number += 1

                print(f"[UDP] Waiting {frequency} seconds before the next execution...")
                time.sleep(frequency)

        except KeyboardInterrupt:
            print(f"[UDP] Stopping periodic execution for device: {device_id}")
        except Exception as e:
            print(f"[DEBUG] Error during periodic execution for {device_id}: {e}")



    def format_task_results(self, results, link_metrics):
        """
        Format the task results into a user-friendly, readable format.

        Args:
            results (dict): The filtered results dictionary.
            link_metrics (dict): The link metrics from the JSON configuration.

        Returns:
            str: A formatted string for user-friendly display.
        """
        formatted_output = []

        # Device ID
        device_id = results.get("device_id", "Unknown")
        formatted_output.append(f"Device ID: {device_id}")

        # Overall status
        status = results.get("status", "Unknown")
        formatted_output.append(f"Status: {status}")

        # CPU Usage
        cpu = results.get("results", {}).get("cpu_usage", {})
        if isinstance(cpu, dict) and cpu.get("status") == "success":
            formatted_output.append(f"  CPU Usage: {cpu.get('cpu_usage')}")
        else:
            formatted_output.append("  CPU Usage: Failed to collect data")

        # RAM Usage
        ram = results.get("results", {}).get("ram_usage", {})
        if isinstance(ram, dict) and ram.get("status") == "success":
            formatted_output.append(f"  RAM Usage: {ram.get('ram_usage')}")
        else:
            formatted_output.append("  RAM Usage: Failed to collect data")

        # Interface Statistics
        interface_stats = results.get("results", {}).get("interface_stats", {})
        if isinstance(interface_stats, dict) and interface_stats.get("status") == "success":
            formatted_output.append("  Network Interfaces:")
            for iface, stats in interface_stats.get("interface_stats", {}).items():
                if isinstance(stats, dict) and stats.get("status") == "failure":
                    formatted_output.append(f"    {iface}: {stats.get('error')}")
                else:
                    formatted_output.append(
                        f"    {iface}: TX Packets: {stats['tx_packets']}, "
                        f"RX Packets: {stats['rx_packets']}, "
                        f"Total Packets: {stats['total_packets']}"
                    )
        else:
            formatted_output.append("  Network Interfaces: Failed to collect data")

        # Latency
        if "latency" in link_metrics:
            latency = results.get("results", {}).get("latency", {})
            if isinstance(latency, dict) and latency.get("status") == "success":
                latency_value = latency.get("latency", "N/A")
                formatted_output.append(f"  Latency: {latency_value} ms")
            elif latency.get("status") == "failure":
                formatted_output.append("  Latency: Failed to collect data")

        # Iperf Results
        if "packet_loss" in link_metrics or "jitter" in link_metrics or "bandwidth" in link_metrics:
            if "packet_loss" in link_metrics:
                packet_loss = results.get("results", {}).get("packet_loss", "N/A")
                if packet_loss != "N/A" and "/" in packet_loss:
                    # Calculate packet loss percentage
                    lost, total = map(int, packet_loss.split("/"))
                    loss_percentage = (lost / total) * 100 if total > 0 else 0
                    formatted_output.append(f"  Packet Loss: {packet_loss} ({loss_percentage:.2f}%)")
                else:
                    formatted_output.append(f"  Packet Loss: {packet_loss}")
            if "jitter" in link_metrics:
                jitter = results.get("results", {}).get("jitter", "N/A")
                formatted_output.append(f"  Jitter: {jitter} ms")
            if "bandwidth" in link_metrics:
                bandwidth = results.get("results", {}).get("bandwidth", "N/A")
                formatted_output.append(f"  Bandwidth: {bandwidth}")

        return "\n".join(formatted_output)



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
            global_frequency = task.get("frequency", 20)  # Default to 20 seconds
            
            print(f"[UDP] Received task seq {seq_number}: {task}")

            # Send task acknowledgment back to the server
            self.send_task_ack(seq_number, addr)

            # Start periodic execution of the task
            self.execute_task_periodically(task, seq_number, addr, global_frequency)

        except struct.error as e:
            print(f"[DEBUG] Struct unpacking error: {e}")
        except json.JSONDecodeError as e:
            print(f"[DEBUG] JSON decoding error: {e}")
        except Exception as e:
            print(f"[DEBUG] Error processing task: {e}")


    def filter_results(self, results, link_metrics):
        """
        Filter the task results to include only the required metrics.

        Args:
            results (dict): The full results dictionary.
            link_metrics (dict): The link metrics required by the task.

        Returns:
            dict: The filtered results dictionary.
        """
        filtered_results = {
            "device_id": results.get("device_id"),
            "status": results.get("status"),
            "results": {}
        }

        # Include CPU usage if present
        if "cpu_usage" in results.get("results", {}):
            filtered_results["results"]["cpu_usage"] = results["results"]["cpu_usage"]

        # Include RAM usage if present
        if "ram_usage" in results.get("results", {}):
            filtered_results["results"]["ram_usage"] = results["results"]["ram_usage"]

        # Include interface stats if present
        if "interface_stats" in results.get("results", {}):
            filtered_results["results"]["interface_stats"] = results["results"]["interface_stats"]

        # Include latency
        if "latency" in link_metrics:
            latency = results.get("results", {}).get("latency", {})
            if latency:
                filtered_results["results"]["latency"] = latency

        # Include iperf-related metrics based on link_metrics
        iperf = results.get("results", {}).get("iperf", {})
        if iperf:
            iperf_results = iperf.get("results", {})
            if "packet_loss" in link_metrics:
                filtered_results["results"]["packet_loss"] = iperf_results.get("packet_loss", "N/A")
            if "jitter" in link_metrics:
                filtered_results["results"]["jitter"] = iperf_results.get("jitter", "N/A")
            if "bandwidth" in link_metrics:
                transfer = iperf_results.get("transfer", "N/A")
                bitrate = iperf_results.get("bitrate", "N/A")
                filtered_results["results"]["bandwidth"] = f"{transfer} transferred, {bitrate} bitrate"

        return filtered_results



    def send_results_to_server(self, seq_number, results, addr, link_metrics, max_retries=3, ack_timeout=5):
        """
        Send the task results back to the server with retransmission logic.

        Args:
            seq_number (int): Sequence number of the task.
            results (dict): Task results to send.
            addr (tuple): Server address (IP, port).
            link_metrics (dict): Link metrics required from the task configuration.
            max_retries (int): Maximum number of retransmission attempts.
            ack_timeout (int): Timeout in seconds to wait for an ACK.
        """
        try:
            # Filter results to include only required metrics
            filtered_results = self.filter_results(results, link_metrics)

            # Add the sequence number to the filtered results
            filtered_results["sequence_number"] = seq_number  # Embed seq_number in the data

            # Format the filtered results for human readability
            formatted_results = self.format_task_results(filtered_results, link_metrics)
            print("[DEBUG] Formatted task results (Agent Side):")
            print(formatted_results)

            # Serialize the results for transmission
            message = struct.pack("!4sI", b"TRES", seq_number) + formatted_results.encode('utf-8')

            # Server address
            server_address = (self.server_ip, 12345)

            # Retransmission loop
            for attempt in range(1, max_retries + 1):
                try:
                    # Send the message to the server
                    self.udp_socket.sendto(message, server_address)
                    print(f"[UDP] Attempt {attempt}: Sending formatted results for seq {seq_number} to {server_address}")

                    # Wait for ACK
                    self.udp_socket.settimeout(ack_timeout)
                    ack_data, _ = self.udp_socket.recvfrom(1024)  # Buffer size of 1024 bytes

                    # Parse the ACK
                    ack_header, ack_seq_number = struct.unpack("!4sI", ack_data[:8])
                    if ack_header == b"TACK" and ack_seq_number == seq_number:
                        print(f"[UDP] Received ACK for seq {seq_number} from {server_address}")
                        break  # Stop retransmitting upon successful ACK

                except socket.timeout:
                    print(f"[UDP] Timeout waiting for ACK for seq {seq_number}")
                except Exception as e:
                    print(f"[UDP] Error during ACK processing: {e}")
            else:
                # If we exhaust all retries
                print(f"[UDP] Failed to send results for seq {seq_number} after {max_retries} attempts")
        except Exception as e:
            print(f"[UDP] Error sending results to server: {e}")




    def check_alert_conditions(self, results, alertflow_conditions):
        """
        Check if the task results exceed the alertflow_conditions.

        Args:
            results (dict): Task results from the metrics.
            alertflow_conditions (dict): Alert thresholds defined in the task.

        Returns:
            list: A list of exceeded metrics. Empty if no alerts.
        """
        exceeded_metrics = []

        # Check CPU usage
        if "cpu_usage" in alertflow_conditions:
            cpu_result = results.get("results", {}).get("cpu_usage", {})
            if cpu_result.get("status") == "success":
                cpu_value = float(cpu_result.get("cpu_usage", "0%").strip('%'))
                if cpu_value > alertflow_conditions["cpu_usage"]:
                    exceeded_metrics.append(f"CPU Usage: {cpu_value}% > {alertflow_conditions['cpu_usage']}%")

        # Check RAM usage
        if "ram_usage" in alertflow_conditions:
            ram_result = results.get("results", {}).get("ram_usage", {})
            if ram_result.get("status") == "success":
                ram_value = float(ram_result.get("ram_usage", "0%").strip('%'))
                if ram_value > alertflow_conditions["ram_usage"]:
                    exceeded_metrics.append(f"RAM Usage: {ram_value}% > {alertflow_conditions['ram_usage']}%")

        # Check Interface stats
        if "interface_stats" in alertflow_conditions:
            interface_result = results.get("results", {}).get("interface_stats", {})
            if interface_result.get("status") == "success":
                for iface, stats in interface_result.get("interface_stats", {}).items():
                    if stats.get("status") != "failure":
                        total_packets = stats.get("total_packets", 0)
                        if total_packets > alertflow_conditions["interface_stats"]:
                            exceeded_metrics.append(f"Interface {iface}: {total_packets} packets > {alertflow_conditions['interface_stats']} packets")

        # Check Packet Loss
        if "packet_loss" in alertflow_conditions:
            packet_loss = results.get("results", {}).get("packet_loss", "N/A")
            if packet_loss != "N/A" and "/" in packet_loss:
                lost, total = map(int, packet_loss.split("/"))
                loss_percentage = (lost / total) * 100 if total > 0 else 0
                if loss_percentage > alertflow_conditions["packet_loss"]:
                    exceeded_metrics.append(f"Packet Loss: {loss_percentage:.2f}% > {alertflow_conditions['packet_loss']}%")

        # Check Jitter
        if "jitter" in alertflow_conditions:
            jitter = results.get("results", {}).get("jitter", "N/A")
            if jitter != "N/A":
                jitter_value = float(jitter.strip(' ms'))
                if jitter_value > alertflow_conditions["jitter"]:
                    exceeded_metrics.append(f"Jitter: {jitter_value} ms > {alertflow_conditions['jitter']} ms")

        return exceeded_metrics

    def send_alert_to_server(self, exceeded_metrics, device_id):
        """
        Send an alert to the server using TCP.

        Args:
            exceeded_metrics (list): List of exceeded metrics to send in the alert.
            device_id (str): The ID of the device sending the alert.
        """
        alert_message = {
            "agent_id": self.agent_id,
            "device_id": device_id,
            "exceeded_metrics": exceeded_metrics
        }
        alert_data = json.dumps(alert_message).encode('utf-8')

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
                tcp_socket.connect((self.server_ip, self.server_port))
                tcp_socket.sendall(alert_data)
                print(f"[TCP] Alert sent to server: {alert_message}")

            # Increment alert count for this device
            self.alert_counts[device_id] = self.alert_counts.get(device_id, 0) + 1
            print(f"[DEBUG] Alert count for {device_id}: {self.alert_counts[device_id]}")

        except Exception as e:
            print(f"[TCP] Error sending alert to server: {e}")



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 NMS_Agent.py <server_ip> <agent_id>")
        sys.exit(1)

    server_ip = sys.argv[1]  # First argument: Server IP
    agent_id = sys.argv[2]   # Second argument: Agent ID
    agent = NMS_Agent(server_ip, 12345, agent_id)
    agent.send_ack()
    agent.receive_tasks()
