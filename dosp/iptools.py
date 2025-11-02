def ip_to_int(ip_str: str) -> int | None:
    """
     Convert vIP into int
     :param ip_str: "0.0.0.0"-like str
     :except ValueError
    """
    if not isinstance(ip_str, str) or len(ip_str.split('.')) != 4:
        return None
    for _ in ip_str.split('.'):
        if not _.isdigit():
            return None
    parts = list(map(int, ip_str.split('.')))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def int_to_ip(ip_int: int) -> str | None:
    """
    Convert int into vIP
    :param ip_int: int of vIP
    :return:
    """
    if not isinstance(ip_int, int) or ip_int < 0 or ip_int > 0xFFFFFFFF:
        return None
    return '.'.join(str((ip_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))

def ip_to_id(ip: str | int) -> int | None:
    if isinstance(ip, str) and len(ip.split('.')) == 4:
        return int(ip.split('.')[-1])
    elif isinstance(ip, int):
        return int(int_to_ip(ip).split(".")[-1])
    return None