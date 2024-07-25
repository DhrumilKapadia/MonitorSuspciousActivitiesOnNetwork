import scapy.all as scapy
import sqlite3
import time

# Dictionary to track traffic volume
traffic_volume = {}
# Dictionary to track port scanning attempts
port_attempts = {}


def list_interfaces():
    try:
        # List network interfaces using scapy
        interfaces = scapy.get_if_list()

        if not interfaces:
            print("No network interfaces found.")
            return []

        # Display available network interfaces
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i + 1}:")
            print(f"  Raw Name: {iface}")
            print()

        return interfaces
    except Exception as e:
        print(f"Error listing interfaces: {e}")
        return []


def log_packet(pkt):
    try:
        # Extract IP details
        src_ip = pkt[scapy.IP].src if scapy.IP in pkt else 'N/A'
        dst_ip = pkt[scapy.IP].dst if scapy.IP in pkt else 'N/A'
        protocol = pkt.proto if hasattr(pkt, 'proto') else 'N/A'

        # Print packet details
        print(f"Captured Packet: {pkt.summary()}")
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Summary: {pkt.summary()}")
        print("-" * 50)

        # Log packet to the database
        conn = sqlite3.connect('network_traffic.db')
        cursor = conn.cursor()
        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS packets
                          (timestamp TEXT, src_ip TEXT, dst_ip TEXT, protocol TEXT, summary TEXT)''')
        # Insert packet data
        cursor.execute('''INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, summary)
                          VALUES (?, ?, ?, ?, ?)''', (
            time.strftime('%Y-%m-%d %H:%M:%S'),
            src_ip,
            dst_ip,
            protocol,
            pkt.summary()
        ))
        conn.commit()

        # Check for suspicious activity
        if detect_suspicious_activity(pkt):
            log_alert("Suspicious activity detected!")

        conn.close()

    except Exception as e:
        print(f"Error logging packet: {e}")


def log_alert(message):
    try:
        conn = sqlite3.connect('network_traffic.db')
        cursor = conn.cursor()
        # Create alerts table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS alerts
                          (timestamp TEXT, message TEXT)''')
        # Insert alert data
        cursor.execute('''INSERT INTO alerts (timestamp, message)
                          VALUES (?, ?)''', (
            time.strftime('%Y-%m-%d %H:%M:%S'),
            message
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging alert: {e}")


def detect_suspicious_activity(pkt):
    try:
        src_ip = pkt[scapy.IP].src if scapy.IP in pkt else None
        dst_ip = pkt[scapy.IP].dst if scapy.IP in pkt else None
        protocol = pkt.proto if hasattr(pkt, 'proto') else None

        # High volume of traffic detection
        traffic_threshold = 100
        traffic_volume[src_ip] = traffic_volume.get(src_ip, 0) + 1
        if traffic_volume[src_ip] > traffic_threshold:
            log_alert("High volume of traffic detected.")
            return True

        # Port scanning detection
        if protocol == 6:  # TCP
            dport = pkt[scapy.TCP].dport
            if src_ip in port_attempts:
                port_attempts[src_ip].add(dport)
            else:
                port_attempts[src_ip] = {dport}

            if len(port_attempts[src_ip]) > 50:  # Example port scan threshold
                log_alert("Port scanning detected.")
                return True

        # Unknown IP detection
        known_ips = ['192.168.1.1', '10.0.0.1']
        if src_ip not in known_ips and dst_ip not in known_ips:
            log_alert("Unknown IP detected.")
            return True

        # Suspicious payload detection
        if protocol == 17:  # UDP
            if len(pkt[scapy.Raw].load) > 1000:  # Example size threshold
                log_alert("Suspiciously large UDP payload detected.")
                return True

        return False
    except Exception as e:
        print(f"Error in detecting suspicious activity: {e}")
        return False


def start_capture(interface):
    try:
        # Start capturing packets on the specified interface continuously
        print(f"Starting continuous packet capture on interface {interface}...")
        scapy.sniff(iface=interface, prn=log_packet)

    except Exception as e:
        print(f"Error during packet capture: {e}")


def main():
    # List available network interfaces
    interfaces = list_interfaces()

    if not interfaces:
        return

    # Prompt user to select an interface
    try:
        selection = int(input("Select an interface number: ")) - 1
        if selection < 0 or selection >= len(interfaces):
            print("Invalid selection.")
            return

        selected_interface = interfaces[selection]
        start_capture(selected_interface)

    except ValueError:
        print("Invalid input. Please enter a number.")


if __name__ == "__main__":
    main()
