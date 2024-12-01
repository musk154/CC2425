import subprocess

class MetricCollector:
    def collect_cpu_usage(self):
        """
        Simulate the collection of CPU usage.
        Returns:
            str: Simulated CPU usage percentage.
        """
        return "Simulated CPU Usage: 45%"

    def collect_ram_usage(self):
        """
        Simulate the collection of RAM usage.
        Returns:
            str: Simulated RAM usage percentage.
        """
        return "Simulated RAM Usage: 65%"

    def collect_interface_stats(self, interfaces):
        """
        Simulate the collection of network interface statistics.

        Args:
            interfaces (list): List of network interfaces.

        Returns:
            dict: Simulated statistics for each interface.
        """
        stats = {}
        for interface in interfaces:
            stats[interface] = {
                "tx_packets": 1000,  # Simulated transmitted packets
                "rx_packets": 900,   # Simulated received packets
                "tx_bytes": 1000000, # Simulated transmitted bytes
                "rx_bytes": 950000   # Simulated received bytes
            }
        return stats

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
            role (str): 'client' or 'server'.
            duration (int): Duration of the test in seconds.
            protocol (str): 'TCP' or 'UDP'.

        Returns:
            dict: Results of the iperf command.
        """
        try:
            command = ["iperf3"]
            if role == "client":
                command += ["--client", server]
            else:
                command += ["--server"]

            command += ["--time", str(duration)]

            if protocol.upper() == "UDP":
                command += ["--udp"]

            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout
                # Parse output to extract metrics
                return {"output": output, "status": "success"}
            else:
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
