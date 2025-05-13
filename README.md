# Security System

A Python-based security system for user authentication and protected data management.

## Overview

This project implements a secure user authentication system with features for user registration, login, password management, and protected data storage. It includes role-based access control with admin and user roles, account freeze protection, and emergency password reset capabilities.

## Features

- **User Authentication**: Secure login with username and SHA-256 hashed passwords.
- **Role-Based Access**: Admin and user roles with different permissions.
- **Account Protection**: Limits login attempts and freezes accounts after too many failed attempts (default: 5 attempts, 30-second freeze).
- **Data Management**: Stores user credentials and protected data (notes and files) in JSON files.
- **Admin Functions**: Admins can register new users and reset passwords.
- **Emergency Reset**: Allows users to reset their password via a verification code.
- **Cross-Platform**: Works on Windows, Linux, and macOS with appropriate console clearing.

## Requirements

- Python 3.6+
- Standard libraries: `os`, `time`, `json`, `hashlib`, `platform`, `datetime`

No external dependencies are required.

## Installation

1. Clone or download the repository.
2. Ensure Python 3.6+ is installed.
3. Place the script (`security_system.py`) in your desired directory.

## Usage

1. Run the script:
   ```bash
   python security_system.py
2. If no users exist, the system prompts to create the first user (automatically an admin).
3. Main menu options:
  - Login: Access the system with a username and password.
  - Change Data Directory: Switch to a new directory for storing user data.
  - Emergency Profile Reset: Reset a forgotten password using a verification code.
  - Exit: Close the application.
4. After login, users can:
  - View and add secure notes.
  - Change their password.
  - Admins can additionally register new users and reset other users' passwords.

## File Structure

- security_system.py: Main script containing the SecuritySystem class.
- data/ (created automatically):
  - user_data.json: Stores user credentials (username, hashed password, role).
  - protected_data.json: Stores user-specific protected data (notes and files).


## Security Notes

- Passwords are hashed using SHA-256 for secure storage.
- Account freeze mechanism prevents brute-force attacks.
- The emergency reset uses a demo verification code (MD5-based); in a production system, this would be sent via email or SMS.
- Data is stored in plain JSON files; for production, consider encryption or a secure database.

## Limitations

- No GUI; operates via command-line interface.
- Passwords are hashed but not salted (SHA-256 only).
- File-based storage is not optimized for large-scale use.
- Emergency reset is a demo implementation and not suitable for production without secure delivery of verification codes.

## Contributing

Feel free to fork the repository and submit pull requests for improvements. Suggestions for enhancing security, adding features, or improving the UI are welcome.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
