import os
import time
import json
import hashlib
import platform
from datetime import datetime, timedelta


class SecuritySystem:
    def __init__(self, data_dir=None):
        if data_dir is None:
            self.data_dir = os.path.join(os.getcwd(), "data")
        else:
            self.data_dir = data_dir
            
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        
        self.user_data_file = os.path.join(self.data_dir, "user_data.json")
        self.protected_data_file = os.path.join(self.data_dir, "protected_data.json")
        
        self.max_attempts = 5
        self.freeze_duration = 30  
        
        print(f"Initializing Security System...")
        print(f"System Details: {platform.system()} {platform.release()}")
        print(f"User data file: {os.path.abspath(self.user_data_file)}")
        print(f"Protected data file: {os.path.abspath(self.protected_data_file)}")
        
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
                print("Error reading user data file. Creating new file.")
                return {}
        else:
            print("User data file does not exist. Creating new empty file.")
            empty_users = {}
            self.save_users(empty_users)
            return empty_users

    def load_protected_data(self):
        """Load protected data from file or create if not exists"""
        if os.path.exists(self.protected_data_file):
            try:
                with open(self.protected_data_file, 'r') as file:
                    return json.load(file)
            except json.JSONDecodeError:
                return {}
        else:
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
                    self.login_attempts[username]["count"] = 0
                    self.login_attempts[username]["freeze_time"] = None
        return False

    def register_user(self, admin_username=None):
        """Register a new user (admin only or first user becomes admin)"""
        first_user = len(self.users) == 0
        
        if not first_user and admin_username is not None:
            if admin_username not in self.users or self.users[admin_username]["role"] != "admin":
                print("Permission denied. Only admins can register new users.")
                return False
            
        print("\n==== USER REGISTRATION ====")
        new_username = input("Enter new username: ").strip()
        
        if new_username in self.users:
            print("Username already exists!")
            return False
            
        password = input("Enter password: ")
        confirm_password = input("Confirm password: ")
        
        if password != confirm_password:
            print("Passwords do not match!")
            return False
        
        if first_user:
            role = "admin"
            print("First user created will be an administrator.")
        else:
            role = input("Enter role (admin/user): ").strip().lower()
            if role not in ["admin", "user"]:
                role = "user"  
        
        hashed_password = self.hash_password(password)
        print(f"Password hash created: {hashed_password[:10]}...{hashed_password[-10:]}")
            
        self.users[new_username] = {
            "password": hashed_password,
            "role": role
        }
        
        self.protected_data[new_username] = {
            "notes": [],
            "files": []
        }
        
        self.save_users(self.users)
        self.save_protected_data(self.protected_data)
        
        print(f"User '{new_username}' created successfully with role '{role}'!")
        return True

    def login(self):
        """User login with attempt limiting"""
        print("\n==== SECURITY SYSTEM LOGIN ====")
        username = input("Username: ").strip()
        
        if username not in self.users:
            print("Invalid username or password")
            time.sleep(1)
            return None
        
        if username not in self.login_attempts:
            self.login_attempts[username] = {"count": 0, "freeze_time": None}

        while True:
            if self.is_frozen(username):
                return None
                
            password = input("Password: ")  
            hashed_password = self.hash_password(password)
            
            if hashed_password == self.users[username]["password"]:
                self.login_attempts[username]["count"] = 0
                print(f"\nWelcome, {username}!")
                input("Press Enter to continue...")
                return username
            else:
                self.login_attempts[username]["count"] += 1
                attempts_left = self.max_attempts - self.login_attempts[username]["count"]
                
                if attempts_left <= 0:
                    print("\nToo many failed attempts! Account frozen.")
                    self.login_attempts[username]["freeze_time"] = datetime.now() + timedelta(seconds=self.freeze_duration)
                    time.sleep(3)  
                    return None
                else:
                    print(f"Invalid password. {attempts_left} attempts remaining.")
                    print("Try again or press Ctrl+C to cancel login.")
                    time.sleep(1)

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

    def admin_reset_password(self):
        """Allow admin to reset any user's password"""
        print("\n==== ADMIN PASSWORD RESET ====")
        print("Available users:")
        for username, data in self.users.items():
            role = data["role"]
            print(f"- {username} ({role})")
        
        target_username = input("\nEnter username to reset: ").strip()
        
        if target_username not in self.users:
            print(f"User '{target_username}' does not exist.")
            return
            
        new_password = input("Enter new password for user: ")
        confirm_password = input("Confirm new password: ")
        
        if new_password != confirm_password:
            print("Passwords do not match!")
            return
            
        self.users[target_username]["password"] = self.hash_password(new_password)
        self.save_users(self.users)
        print(f"Password for {target_username} has been reset successfully!")
        
    def emergency_profile_reset(self):
        """Emergency function to reset a user profile when password is forgotten"""
        print("\n==== EMERGENCY PROFILE RESET ====")
        print("WARNING: This will reset your password but preserve your data.")
        print("You will need to verify your identity to proceed.")
        
        username = input("\nEnter your username: ").strip()
        
        if username not in self.users:
            print("Username not found.")
            time.sleep(2)
            return
            
        print(f"\nIdentity verification for {username}:")
        
        reset_seed = username + datetime.now().strftime("%Y%m%d")
        reset_code = hashlib.md5(reset_seed.encode()).hexdigest()[:6].upper()
        
        print("\nIn a real system, a verification code would be sent to your")
        print("registered email or phone. For this demo, use this code:")
        print(f"SECURITY CODE: {reset_code}")
        
        attempt = input("\nEnter the security code: ").strip().upper()
        
        if attempt != reset_code:
            print("Invalid security code. Reset failed.")
            time.sleep(2)
            return
            
        new_password = input("Enter new password: ")
        confirm_password = input("Confirm new password: ")
        
        if new_password != confirm_password:
            print("Passwords do not match! Reset canceled.")
            return
            
        self.users[username]["password"] = self.hash_password(new_password)
        self.save_users(self.users)
        
        print(f"\nPassword for {username} has been reset successfully!")
        print("You can now log in with your new password.")

    def run(self):
        """Main system loop"""
        if len(self.users) == 0:
            print("\nNo users exist. You must create the first user.")
            self.register_user()
            input("\nPress Enter to continue...")
        
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print("\n===== SECURITY SYSTEM =====")
            print(f"Data location: {self.data_dir}")
            print("1. Login")
            print("2. Change Data Directory")
            print("3. Emergency Profile Reset")
            print("4. Exit")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == "1":
                username = self.login()
                if username:
                    self.user_menu(username)
            elif choice == "2":
                new_dir = input("\nEnter new data directory path (leave blank to cancel): ").strip()
                if new_dir:
                    if not os.path.exists(new_dir):
                        try:
                            os.makedirs(new_dir)
                            print(f"Created new directory: {new_dir}")
                        except Exception as e:
                            print(f"Error creating directory: {e}")
                            input("\nPress Enter to continue...")
                            continue
                    
                    print(f"Switching to new data directory: {new_dir}")
                    input("Press Enter to confirm...")
                    
                    new_system = SecuritySystem(new_dir)
                    new_system.run()
                    return  
            elif choice == "3":
                self.emergency_profile_reset()
                input("\nPress Enter to continue...")
            elif choice == "4":
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
                print("5. Reset User Password")
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
            elif choice == "5" and self.users[username]["role"] == "admin":
                self.admin_reset_password()
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
