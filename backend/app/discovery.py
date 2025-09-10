import ipaddress
import subprocess

def discover_hosts(subnet: str):
    """Ping sweep a subnet to find alive hosts."""
    alive_hosts = []
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return {"error": "Invalid subnet"}

    for ip in net.hosts():
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            alive_hosts.append(str(ip))

    return {
        "subnet": subnet,
        "alive_hosts": alive_hosts,
        "count": len(alive_hosts)
    }
