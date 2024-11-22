import socket
import sys
import json

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
