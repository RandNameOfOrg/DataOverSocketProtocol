def ip_to_int(ip_str: str) -> int:
    parts = list(map(int, ip_str.split('.')))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def int_to_ip(ip_int: int) -> str:
    return '.'.join(str((ip_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))
