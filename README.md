# KineticLull - Setup Guide

## Overview

KineticLull is a powerful web application designed to streamline the management and deployment of External Dynamic Lists (EDLs). EDLs are critical tools for network security, allowing administrators to dynamically update firewall policies based on real-time changes to IP addresses, URLs, and domain lists hosted externally. KineticLull simplifies this process, providing a user-friendly interface for creating, managing, and deploying EDLs without direct firewall access.

## Key Features

- **EDL Management**: Users can create and manage EDLs directly through KineticLull's interface. This includes adding, updating, and removing entries such as URLs, FQDNs, IP hosts/subnets.

- **Access Control Lists (ACLs)**: Each EDL comes with an associated ACL that can be configured to limit access to the EDL. This feature ensures that only authorized users or systems can access sensitive EDLs.

- **API Integration**: KineticLull supports API integration, allowing EDLs to be uploaded programatically. This does not automatically create the EDL as the submission via API has to be reviewed and saved by an administrator.  Future versions will allow EDLs to be updated once approved.

- **Cloning and Deletion**: EDLs can be easily cloned, allowing users to create duplicates for different purposes or backup. EDLs can also be deleted when no longer needed.

- **Backup and Export**: EDLs can be downloaded as text files, providing a simple method for backup or use in other systems.

- **API Key Generation**: While there is no default API key, KineticLull allows users to generate API keys. This feature facilitates secure API integration for automated EDL management.

- **Security Analyst Empowerment**: By abstracting EDL management from direct firewall access, KineticLull empowers security analysts to update EDLs as needed. This capability ensures that security policies can be rapidly adapted to emerging threats without compromising firewall security or providing wide access.

- **Documentation and Notes**: KineticLull supports maintaining detailed notes for each EDL, allowing users to document the purpose, changes, or any other relevant information for future reference.

## Getting Started

To set up KineticLull for your organization, please follow the setup instructions detailed in the Setup Instructions section. Ensure that you have Python 3.12 or higher installed on your system before beginning the installation process.

## Contributing

Contributions to KineticLull are welcome! Please refer to our contributing guidelines for more information on how to contribute to the project.


## Setup Instructions

### 1. Clone the Repository

Start by cloning the project repository to your local system or server.

```
git clone https://github.com/greaselovely/KineticLull
cd KineticLull
```

## Run the Setup Script

We've provided a setup.sh script to streamline the initial setup process, which includes creating a virtual environment, installing dependencies, and setting up initial configurations.

```
chmod +x setup.sh
./setup.sh
```

Note: The script will prompt you for the necessary configuration settings (such as the IP or FQDN where the application will be accessible) during its execution. These settings are crucial for the proper functioning of the application.

## Review and Adjust Configuration

After running the setup script, it's important to review the generated .env file and any other configuration settings. Adjust any settings as necessary to fit your specific environment or requirements.

## Running the Application

To run the application in a manner suited for internal use, testing, or demonstration, you can utilize Django's built-in development server. While not recommended for production use, this server is suitable for scenarios where ease of setup and use is prioritized.

```
source venv/bin/activate
python manage.py runserver 127.0.0.1:8000 &
```

This command starts the Django development server, making the application accessible on port 8000 of your machine or server. Replace 127.0.0.1 with your specific IP address and port if you want to restrict access to a particular network interface.

## Default Credentials

A default superuser account is created during the setup process for accessing the Django admin interface:

    Username: support@kineticlull.com
    Password: Password!

For security purposes, please change the default credentials immediately after the setup is complete.

## About EDLs

External Dynamic Lists (EDLs) play a critical role in this project by allowing dynamic updates and enforcement of firewall policies based on real-time changes to the lists without needing manual configuration adjustments on the firewall.

## Complimentary Tools

Refer to GhostHunter for Firefox and Chrome.

## Testing API

Use the following to test API against the provided database (changing IP and port as needed):

```
curl -X POST http://<<your ip address>>:<<your port number>>/api/submit_fqdn/
    -H "Content-Type: application/json" -H "Authorization: Bearer <<your api key here>>" 
    -d '{"fqdn_list": ["example1.com", "example2.net", "example3.org", "example4.io", "example5.co"]}'
```
