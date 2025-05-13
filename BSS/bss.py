import os
import time
import json
import hashlib
import getpass
from datetime import datetime, timedelta

class SecuritySystem:
    def __init__(self):
        self.user_data_file = "user_data.json"
        self.protected_data_file = "protected_data.json"
        self.max_attempts = 5
        self.freeze_duration = 30  # seconds
        self.users = self.load_users()
        self.protected_data = self.load_protected_data()
        self.login_attempts = {}

    def load_users(self):
        """Load user credentials from file or create if not exists"""
        if os.path.exists(self.user_data_file):
            try:
                with open(self.user_data_file, 'r') as file:
                    return json.load(file)
            except json.JSONDecodeError:
                return {}
        else:
            # Create default admin user if file doesn't exist
            default_users = {
                "admin": {
                    "password": self.hash_password("admin123"),
                    "role": "admin"
                }
            }
            self.save_users(default_users)
            return default_users

    def load_protected_data(self):
        """Load protected data from file or create if not exists"""
        if os.path.exists(self.protected_data_file):
            try:
                with open(self.protected_data_file, 'r') as file:
                    return json.load(file)
            except json.JSONDecodeError:
                return {}
        else:
            # Create sample protected data
            default_data = {
                "admin": {
                    "notes": ["This is a secure note for admin"],
                    "files": ["admin_document1.txt"]
                }
            }
            self.save_protected_data(default_data)
            return default_data

    def save_users(self, users):
        """Save user credentials to file"""
        with open(self.user_data_file, 'w') as file:
            json.dump(users, file, indent=4)

    def save_protected_data(self, data):
        """Save protected data to file"""
        with open(self.protected_data_file, 'w') as file:
            json.dump(data, file, indent=4)

    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def is_frozen(self, username):
        """Check if account is frozen due to too many failed attempts"""
        if username in self.login_attempts:
            if self.login_attempts[username]["count"] >= self.max_attempts:
                freeze_time = self.login_attempts[username]["freeze_time"]
                if freeze_time and datetime.now() < freeze_time:
                    time_left = (freeze_time - datetime.now()).seconds
                    print(f"\nAccount is frozen. Try again in {time_left} seconds.")
                    return True
                else:
                    # Reset attempts if freeze time has passed
                    self.login_attempts[username]["count"] = 0
                    self.login_attempts[username]["freeze_time"] = None
        return False

    def register_user(self, admin_username):
        """Register a new user (admin only)"""
        if admin_username not in self.users or self.users[admin_username]["role"] != "admin":
            print("Permission denied. Only admins can register new users.")
            return False
            
        print("\n==== USER REGISTRATION ====")
        new_username = input("Enter new username: ").strip()
        
        if new_username in self.users:
            print("Username already exists!")
            return False
            
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match!")
            return False
            
        role = input("Enter role (admin/user): ").strip().lower()
        if role not in ["admin", "user"]:
            role = "user"  # Default to user role
            
        # Add new user
        self.users[new_username] = {
            "password": self.hash_password(password),
            "role": role
        }
        
        # Create empty protected data for the new user
        self.protected_data[new_username] = {
            "notes": [],
            "files": []
        }
        
        # Save changes
        self.save_users(self.users)
        self.save_protected_data(self.protected_data)
        
        print(f"User '{new_username}' created successfully with role '{role}'!")
        return True

    def login(self):
        """User login with attempt limiting"""
        print("\n==== SECURITY SYSTEM LOGIN ====")
        username = input("Username: ").strip()
        
        # Check if user exists
        if username not in self.users:
            print("Invalid username or password")
            return None
            
        # Check if account is frozen
        if self.is_frozen(username):
            return None
            
        # Initialize attempt counter if not exists
        if username not in self.login_attempts:
            self.login_attempts[username] = {"count": 0, "freeze_time": None}
            
        # Get password
        password = getpass.getpass("Password: ")
        hashed_password = self.hash_password(password)
        
        # Verify password
        if hashed_password == self.users[username]["password"]:
            # Reset login attempts on successful login
            self.login_attempts[username]["count"] = 0
            print(f"\nWelcome, {username}!")
            return username
        else:
            # Increment failed attempts
            self.login_attempts[username]["count"] += 1
            attempts_left = self.max_attempts - self.login_attempts[username]["count"]
            
            if attempts_left <= 0:
                print("\nToo many failed attempts! Account frozen.")
                self.login_attempts[username]["freeze_time"] = datetime.now() + timedelta(seconds=self.freeze_duration)
                time.sleep(3)  # Brief pause to show the message
            else:
                print(f"Invalid username or password. {attempts_left} attempts remaining.")
                
            return None

    def add_note(self, username):
        """Add a note to user's protected data"""
        if username not in self.protected_data:
            self.protected_data[username] = {"notes": [], "files": []}
            
        note = input("\nEnter your note: ")
        self.protected_data[username]["notes"].append(note)
        self.save_protected_data(self.protected_data)
        print("Note added successfully!")

    def view_notes(self, username):
        """View user's protected notes"""
        if username not in self.protected_data or not self.protected_data[username]["notes"]:
            print("\nNo notes found.")
            return
            
        print("\n==== YOUR NOTES ====")
        for i, note in enumerate(self.protected_data[username]["notes"], 1):
            print(f"{i}. {note}")

    def change_password(self, username):
        """Allow user to change their password"""
        current_password = getpass.getpass("\nEnter current password: ")
        hashed_current = self.hash_password(current_password)
        
        if hashed_current != self.users[username]["password"]:
            print("Incorrect password!")
            return False
            
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password != confirm_password:
            print("Passwords do not match!")
            return False
            
        self.users[username]["password"] = self.hash_password(new_password)
        self.save_users(self.users)
        print("Password changed successfully!")
        return True

    def run(self):
        """Main system loop"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n===== SECURITY SYSTEM =====")
            print("1. Login")
            print("2. Exit")
            
            choice = input("\nEnter your choice (1-2): ")
            
            if choice == "1":
                username = self.login()
                if username:
                    self.user_menu(username)
            elif choice == "2":
                print("\nExiting system. Goodbye!")
                break
            else:
                print("Invalid choice. Try again.")
                time.sleep(1)

    def user_menu(self, username):
        """Display user menu after successful login"""
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"\n===== Welcome {username} =====")
            print("1. View Notes")
            print("2. Add Note")
            print("3. Change Password")
            if self.users[username]["role"] == "admin":
                print("4. Register New User")
            print("0. Logout")
            
            choice = input("\nEnter your choice: ")
            
            if choice == "1":
                self.view_notes(username)
                input("\nPress Enter to continue...")
            elif choice == "2":
                self.add_note(username)
                input("\nPress Enter to continue...")
            elif choice == "3":
                self.change_password(username)
                input("\nPress Enter to continue...")
            elif choice == "4" and self.users[username]["role"] == "admin":
                self.register_user(username)
                input("\nPress Enter to continue...")
            elif choice == "0":
                print("Logging out...")
                time.sleep(1)
                break
            else:
                print("Invalid choice. Try again.")
                time.sleep(1)


if __name__ == "__main__":
    security_system = SecuritySystem()
    security_system.run()