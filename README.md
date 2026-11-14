System Information Gathering Tool

A Python-based system enumeration tool designed for authorized penetration testers, offensive security engineers, and security researchers.

This tool helps security professionals collect and review available information about a target system after obtaining authorized access.

Features

The tool collects the following information, when available:

System Information
Operating system and version
Hostname
Architecture
Kernel version
CPU and RAM information
System uptime
User and Account Information
Current logged-in user
Local user accounts
Group membership
Administrator/root account information
User profiles
Privilege and Permission Information
Current user privileges
Administrative permissions
User and group permissions
Sudo configuration information
File and directory permissions
Network Information
IP addresses
MAC addresses
Network interfaces
Default gateway
DNS configuration
Active network connections
Routing information
Running Processes and Services
Running processes
Process IDs
Process owners
Running services
Service information
Scheduled tasks
Installed Software Information
Installed applications
Software versions
Package information
Development tools
Database software
Security software
Sensitive File and Data Discovery
Configuration files
Log files
Backup files
Environment configuration
SSH configuration files
Potentially exposed sensitive files
Requirements
Python 3.x
Operating system: Windows / Linux (depending on supported features)
Required Python libraries
Installation

Clone the repository:

bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git


Navigate to the project directory:

bash
cd YOUR-REPOSITORY


Install dependencies:

bash
pip install -r requirements.txt

Usage

Run the Python script:

bash
python3 main.py


On Windows:

bash
python main.py


Some information may require elevated privileges to access.

Project Purpose

The main objective of this project is to simplify system information gathering and enumeration by collecting multiple categories of system information through a single Python script.

It can be useful for:

Authorized penetration testing
Offensive security assessments
Security research
System auditing
Cybersecurity learning
Post-exploitation security assessments
Disclaimer

This tool is developed strictly for educational purposes and authorized security testing.

Use it only on systems you own or have explicit permission to assess.

The developer is not responsible for any misuse or unauthorized activity.

Contributions

Contributions, suggestions, and improvements are welcome.

Feel free to fork this repository and submit a pull request.

License

Add your preferred open-source license (for example, MIT License).
