# KineticLull

## Overview

KineticLull is a powerful web application designed to streamline the management and deployment of External Dynamic Lists (EDLs). These lists are indispensable for network security, enabling dynamic updates to firewall policies based on real-time changes. KineticLull offers a user-friendly interface for the effortless creation, management, and deployment of EDLs without requiring direct firewall access.

## Key Features

- **EDL Management**: Direct interface for creating, managing, and deploying EDLs.
- **Access Control Lists (ACLs)**: Configurable ACLs for each EDL to ensure secure access.
- **API Integration**: Supports API integration for programmatically uploading EDLs, subject to admin review.
- **Cloning and Deletion**: Simple cloning and deletion of EDLs for flexible management.
- **Backup and Export**: Easy backup and export options for EDLs.
- **API Key Generation**: Secure API key generation for automated EDL management.
- **Security Analyst Empowerment**: Allows security analysts to update EDLs swiftly in response to emerging threats.
- **Documentation and Notes**: Detailed documentation and note-keeping for each EDL.

## Currently Tested and Supported OS:

- Ubuntu Desktop and Server 20 & 22
- Fedora Workstation and Server 39

## Initial Setup

To initiate KineticLull, it's essential that your system is equipped with Python 3.12. Below are detailed instructions to get KineticLull ready for your organization.

After securing Python 3.12, it's crucial to install `pip` and the Python 3.12 virtual environment package (`python3.12-venv`). Skipping these installations will cause operational issues. Our setup script specifically searches for Python 3.12 in `/usr/bin/python3.12`. Should your Python installation reside elsewhere, you'll need to adjust the script's path accordingly.

We've provided a script to streamline the installation of Python 3.12, pip, and venv. Execute `bash install_python.sh` and adhere to the on-screen instructions. With the completion of this step, you're all set to proceed with the subsequent setup stages.

## Setup Instructions

### 1. Clone the Repository

TL;DR at the bottom.
Clone the KineticLull repository to your local system or server making sure you are in the desired installation path:

```
git clone https://github.com/greaselovely/KineticLull.git
cd KineticLull
```

### 2. Run the Setup Script

Execute the provided `setup.sh` script to automate the initial setup. This script handles the creation of a virtual environment, installation of dependencies, and initial configuration:

```
bash setup.sh
```

**Note**: During execution, the script will prompt for necessary configurations, such as the IP address or FQDN for application access. These configurations are vital for the application's functionality.

### 3. Review and Adjust Configuration

Post-setup, ensure to review and adjust configurations in the generated `project/.env` file or other configuration files to meet your specific needs.

### 4. Running the Application

The `setup.sh` file should get you all the information you need to get this running under systemd

### 5. Default Credentials

Upon setup, a default superuser account is created for admin access:

- **Username**: support@kineticlull.com
- **Password**: Password!

Change these credentials immediately for security purposes.

## About EDLs

External Dynamic Lists (EDLs) are central to KineticLull, allowing for dynamic firewall policy updates based on real-time list changes without manual firewall configurations.

## Complimentary Tools

For complementary tools, check out GhostHunter for Firefox and Chrome.

## Contributing

Contributions are welcome! Submit applicable PRs to contribute to KineticLull.


## TL;DR

```
git clone https://github.com/greaselovely/KineticLull
cd KineticLull
bash install_python.sh
bash setup.sh
```



## Testing the API

Test the API using the following curl command (adjust IP and port as needed):

```
curl -X POST https://<<your ip address>>:<<your port number>>/api/submit_fqdn/
    -H "Content-Type: application/json" 
    -H "Authorization: Bearer <<your api key here>>"
    -d '{"fqdn_list": ["example1.com", "example2.net", "example3.org", "example4.io", "example5.co"]}'
```

## API Limitations

Currently, we enforce a limit of 50 objects for any submissions made through scripts or via the GhostHunter tool. Should you try to submit more than this limit, KineticLull will issue a 405 response, and GhostHunter will indicate a thumbs-down symbol. To change this restriction, you have the option to modify the `submit_fqdn` function in the `views.py` file. It's important to proceed with caution when making such adjustments, as we have not performed testing beyond this threshold. Any complications that occur as a result of these changes will be solely your responsibility to address.