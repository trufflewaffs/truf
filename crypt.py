import bcrypt
import hashlib
import time
from passlib.hash import md5_crypt

RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

def verify_bcrypt(stored_hash: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def verify_md5_hash(stored_hash: str, password: str) -> bool:
    return hashlib.md5(password.encode('utf-8')).hexdigest() == stored_hash

def verify_sha1(stored_hash: str, password: str) -> bool:
    return hashlib.sha1(password.encode('utf-8')).hexdigest() == stored_hash

def print_ascii_banner():
    banner = """                                                         
 ____________           _____       _____         
 \           \     _____\    \_   /      |_       
  \           \   /     /|     | /         \      
   |    /\     | /     / /____/||     /\    \     
   |   |  |    ||     | |____|/ |    |  |    \    
   |    \/     ||     |  _____  |     \/      \   
  /           /||\     \|\    \ |\      /\     \  
 /___________/ || \_____\|    | | \_____\ \_____\ 
|           | / | |     /____/| | |     | |     | 
|___________|/   \|_____|    ||  \|_____|\|_____| 
                        |____|/                   
                        
                Hash Cracker
    """
    print(banner)

def check_password(stored_hash: str, password: str, hash_type: str) -> bool:
    if hash_type == '1':
        return verify_bcrypt(stored_hash, password)
    elif hash_type == '2':
        return verify_md5_hash(stored_hash, password)
    elif hash_type == '3':
        return verify_sha1(stored_hash, password)
    return False

def is_hash_valid(hash_type: str, stored_hash: str) -> bool:
    # Check hash format based on the chosen type
    if hash_type == '1':  # BCRYPT
        return stored_hash.startswith('$2a$') or stored_hash.startswith('$2b$') or stored_hash.startswith('$2y$')
    elif hash_type == '2':  # MD5
        return len(stored_hash) == 32 and all(c in '0123456789abcdef' for c in stored_hash)
    elif hash_type == '3':  # SHA-1
        return len(stored_hash) == 40 and all(c in '0123456789abcdef' for c in stored_hash)
    return False

def main():
    while True:  # Added infinite loop to restart after delay
        print_ascii_banner()  
        delay = 0.5
        
        print("Choose hash type to crack:")
        print("1: BCRYPT")
        print("2: MD5")
        print("3: SHA-1")
        
        hash_type = input("Enter your choice (1-3): ")

        stored_hash = input("Put the exact hash to scan: ").strip()
        
        # Validate the hash format
        if not is_hash_valid(hash_type, stored_hash):
            print(f"{RED}please put the exact hash{RESET}")
            time.sleep(5)  # Wait for 5 seconds before the next input
            continue  # Restart the loop

        password_file = 'password.txt'

        with open(password_file, 'r') as file:
            for line in file:
                password_to_check = line.strip()
                if check_password(stored_hash, password_to_check, hash_type):
                    print(f"{GREEN}[FOUND!] {password_to_check}{RESET}")
                    return
                
                print(f"{RED}[NOT FOUND!] {password_to_check}{RESET}")
                time.sleep(delay)

        print(f"{RED}No matching password found.{RESET}")

if __name__ == "__main__":
    main()