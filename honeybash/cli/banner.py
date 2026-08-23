"""HoneyBash CLI Banner & Branding Utility."""

HONEYBASH_BANNER = r"""
  _  _                          ____            _     
 | || |___ _ __  ___ _  _ ___ _|  _ \ __ _ ___| |_   
 | __ / _ \ '  \/ -_) || / _ (_| |_) / _` (_-<| ' \  
 |_||_\___/_|_|_\___|\_, \___(_)____/\__,_/__/|_||_| 
                     |__/                            
   HoneyBash — Modular Network Honeypot Framework
"""


def print_banner():
    """Print the HoneyBash ASCII art banner."""
    print(HONEYBASH_BANNER)
