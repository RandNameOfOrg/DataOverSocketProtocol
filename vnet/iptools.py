def ip_to_int(ip_str: str) -> int | None:
    if not isinstance(ip_str, str) or len(ip_str.split('.')) != 4:
        return None
    parts = list(map(int, ip_str.split('.')))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def int_to_ip(ip_int: int) -> str | None:
    if not isinstance(ip_int, int) or ip_int < 0 or ip_int > 0xFFFFFFFF:
        return None
    return '.'.join(str((ip_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))
