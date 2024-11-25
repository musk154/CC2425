import subprocess

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

