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

## Getting Started

To set up KineticLull, ensure Python 3.12 or higher is installed on your system. Follow the setup instructions below to prepare KineticLull for your organization.

## Setup Instructions

### 1. Clone the Repository

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

Post-setup, ensure to review and adjust configurations in the generated `.env` file or other configuration files to meet your specific needs.

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

Contributions are welcome! Please see our contributing guidelines for details on how to contribute to KineticLull.

## Testing the API

Test the API using the following curl command (adjust IP and port as needed):

```
curl -X POST http://<<your ip address>>:<<your port number>>/api/submit_fqdn/ \
    -H "Content-Type: application/json" -H "Authorization: Bearer <<your api key here>>" \
    -d '{"fqdn_list": ["example1.com", "example2.net", "example3.org", "example4.io", "example5.co"]}'
```
