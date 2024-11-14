import sys

operating_mode: str = 'WAP'
require_ca: bool = False

def get_operating_mode() -> str:
    return operating_mode

def is_m_ca_required() -> bool:
    return require_ca

def display_usage() -> None:
    print("\nUSAGE:")
    print('\n\tpython3 access_point_shell.py [wap rwap] [OPTIONAL: -require_malicious_ca]\n')

def wrong_args(args) -> bool:
    """Check if the arguments are invalid."""
    if len(args) < 2 or len(args) > 3:
        return True
    mode_arg = args[1].lower()
    if mode_arg not in ['wap', 'rwap']:
        return True
    if len(args) == 3:
        ca_arg = args[2].lower()
        if ca_arg != '-require_malicious_ca':
            return True
    return False

def update_settings() -> None:
    global operating_mode, require_ca
    if wrong_args(sys.argv):
        display_usage()
        sys.exit(1)
    operating_mode = sys.argv[1].upper()
    require_ca = False if operating_mode == 'WAP' else '-require_malicious_ca' in [arg.lower() for arg in sys.argv]  

update_settings()
