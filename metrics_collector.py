import subprocess
import psutil

class MetricCollector:
    def collect_cpu_usage(self):
        """
        Collect real CPU usage using psutil.

        Returns:
            dict: A dictionary containing the CPU usage percentage.
        """
        try:
            cpu_usage = psutil.cpu_percent(interval=1)  # Get CPU usage over a 1-second interval
            return {"status": "success", "cpu_usage": f"{cpu_usage:.2f}%"}
        except Exception as e:
            return {"status": "failure", "error": str(e)}

    def collect_ram_usage(self):
        """
        Collect real RAM usage using psutil.

        Returns:
            dict: A dictionary containing the RAM usage percentage.
        """
        try:
            memory = psutil.virtual_memory()  # Get virtual memory stats
            ram_usage = memory.percent  # Get the percentage of RAM used
            return {"status": "success", "ram_usage": f"{ram_usage:.2f}%"}
        except Exception as e:
            return {"status": "failure", "error": str(e)}

    def collect_interface_stats(self, interfaces):
        """
        Simulate interface statistics collection for the provided interfaces.

        Args:
            interfaces (list): List of interface names.

        Returns:
            dict: A dictionary with interface stats for each interface.
        """
        try:
            stats = psutil.net_io_counters(pernic=True)  # Per-interface network stats
            interface_data = {}
            for iface in interfaces:
                if iface in stats:
                    interface_data[iface] = {
                        "tx_packets": stats[iface].packets_sent,
                        "rx_packets": stats[iface].packets_recv,
                        "tx_bytes": stats[iface].bytes_sent,
                        "rx_bytes": stats[iface].bytes_recv
                    }
                else:
                    interface_data[iface] = {"status": "failure", "error": "Interface not found"}
            return {"status": "success", "interface_stats": interface_data}
        except Exception as e:
            return {"status": "failure", "error": str(e)}

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
                return {"error": result.stderr.strip(), "status": "failure"}
        except Exception as e:
            return {"error": str(e), "status": "failure"}


    def iperf(self, server, role, duration, protocol):
        """
        Execute the iperf command for bandwidth and jitter analysis.

        Args:
            server (str): Server address.
            role (str): 'client'.
            duration (int): Duration of the test in seconds.
            protocol (str): 'TCP' or 'UDP'.

        Returns:
            dict: Results of the iperf command.
        """
        try:
            # Ensure the role is client
            if role != "client":
                return {"error": "Invalid role. Only 'client' is supported for tasks.", "status": "failure"}

            # Build the iperf3 command
            command = [
                "iperf3",
                "--client", server,
                "--time", str(duration),
                "--format", "m"  # Use megabits as the output format
            ]
            if protocol.upper() == "UDP":
                command.append("--udp")

            print(f"[DEBUG] Running command: {' '.join(command)}")

            # Run the iperf3 client command
            result = subprocess.run(command, capture_output=True, text=True)

            # Check the result
            if result.returncode == 0:
                return {"output": result.stdout, "status": "success"}
            else:
                # Log the error details for debugging
                print(f"[DEBUG] Command failed with stderr: {result.stderr.strip()}")
                return {"error": result.stderr.strip(), "status": "failure"}
        except Exception as e:
            return {"error": str(e), "status": "failure"}





    def _extract_latency(self, ping_output):
        """
        Extract latency from ping output.

        Args:
            ping_output (str): Raw output from the ping command.

        Returns:
            float: Average latency in ms, or None if parsing fails.
        """
        try:
            for line in ping_output.splitlines():
                if "rtt" in line or "round-trip" in line:
                    avg_latency = line.split("=")[1].split("/")[1]
                    return float(avg_latency)
        except Exception as e:
            print(f"[DEBUG] Error parsing latency: {e}")
        return None
