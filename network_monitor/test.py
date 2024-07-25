import pyshark

# List available interfaces
interfaces = pyshark.LiveCapture.interfaces()
print("Available network interfaces:")
for i in interfaces:
    print(i)
