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
        Collect network interface statistics for the provided interfaces using psutil.

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
                        "total_packets": stats[iface].packets_sent + stats[iface].packets_recv
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


    def iperf(self, server, role="client", duration=10, protocol="tcp", port=None):
        """
        Run iperf3 and collect results.

        Args:
            server (str): The server address for the iperf3 test.
            role (str): The role of the iperf3 instance ('client' or 'server').
            duration (int): Duration of the iperf3 test in seconds.
            protocol (str): Protocol to use ('tcp' or 'udp').
            port (int): The port to use for the iperf3 test.

        Returns:
            dict: Parsed iperf3 results or an error message.
        """
        if port is None:
            raise ValueError("[DEBUG] Port must be specified in the task configuration")

        # Build the iperf3 command
        command = [
            "iperf3",
            f"--{role}", server,
            "--port", str(port),        # Dynamically use the provided port
            "--time", str(duration),
            "--format", "m"
        ]
        if protocol == "udp":
            command.append("--udp")  # Add --udp flag for UDP tests

        print(f"[DEBUG] Running command: {' '.join(command)}")

        try:
            # Run the iperf3 command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=duration + 5
            )

            # Check the command result
            if result.returncode == 0:
                print(f"[DEBUG] Raw iperf output:\n{result.stdout}")
                parsed_results = self._parse_iperf_output(result.stdout)
                print(f"[DEBUG] Parsed iperf results: {parsed_results}")
                return {
                    "status": "success",
                    "results": parsed_results
                }
            else:
                print(f"[DEBUG] Iperf error output:\n{result.stderr}")
                return {
                    "status": "failure",
                    "error": result.stderr.strip()
                }
        except Exception as e:
            print(f"[DEBUG] Exception during iperf execution: {e}")
            return {
                "status": "failure",
                "error": str(e)
            }


    def _parse_iperf_output(self, output):
        """
        Parse the raw iperf output and extract relevant metrics.

        Args:
            output (str): The raw output from the iperf command.

        Returns:
            dict: Parsed metrics including transfer, bitrate, jitter, and packet loss.
        """
        metrics = {
            "transfer": "N/A",
            "bitrate": "N/A",
            "jitter": "N/A",
            "packet_loss": "N/A"
        }

        try:
            lines = output.splitlines()
            print("[DEBUG] Raw iperf output lines:")
            for line in lines:
                print(line)

            for line in lines:
                # Look for "receiver" line with transfer and bitrate
                if "receiver" in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        metrics["transfer"] = parts[4] + " " + parts[5]  # e.g., "1.20 MBytes"
                        metrics["bitrate"] = parts[6] + " " + parts[7]   # e.g., "1.00 Mbits/sec"
                    # Extract "Lost/Total Datagrams" for packet loss
                    if len(parts) >= 12 and "/" in parts[-3]:
                        metrics["packet_loss"] = parts[-3]  # e.g., "39/906"

                # Look for jitter
                if "ms" in line and "/" in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        metrics["jitter"] = parts[8]  # e.g., "0.027"

            print("[DEBUG] Parsed iperf metrics:")
            print(metrics)

        except Exception as e:
            print(f"[DEBUG] Error parsing iperf output: {e}")
        return metrics


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
