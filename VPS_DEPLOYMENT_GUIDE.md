# VPS Deployment Guide

This document provides step-by-step instructions for deploying the server setup script to your VPS using Git.

## Prerequisites

- A VPS running a Debian-based Linux distribution (e.g., Ubuntu, Debian)
- SSH access to your VPS
- Root or sudo privileges on your VPS
- Git installed on your VPS (if not installed, see below)

## Deployment Steps

### 1. Connect to Your VPS

```bash
ssh username@your-vps-ip
```

Replace `username` with your VPS username and `your-vps-ip` with the IP address of your VPS.

### 2. Install Git (if not already installed)

```bash
sudo apt-get update
sudo apt-get install -y git
```

### 3. Clone the Repository

```bash
git clone https://github.com/zachflem/serversetup.git
cd serversetup
```

### 4. Make the Script Executable

```bash
chmod +x server_setup.sh
```

### 5. Run the Script

```bash
sudo ./server_setup.sh
```

The script will guide you through the server setup process with clear prompts and instructions.

## Updating the Script

If you make changes to the script on your local machine and push them to GitHub, you can update the script on your VPS with:

```bash
cd serversetup
git pull
```

## Troubleshooting

If you encounter any issues:

1. Check the log file at `/var/log/server_setup.log` (after running the script)
2. Make sure you're running the script with sudo privileges
3. Verify that your VPS is running a Debian-based distribution

## Security Note

Always review scripts before executing them on your server, especially with elevated privileges. The server_setup.sh script makes significant changes to your system configuration, including creating users, modifying SSH settings, and configuring firewall rules.

## Support

If you encounter issues or have questions, please create an issue on the GitHub repository.
