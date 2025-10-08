# Adding Your SSH Key to VPS for GitHub Authentication

This guide explains how to configure your VPS to authenticate with GitHub using SSH.

## Steps to Configure SSH for GitHub on Your VPS

### 1. Log into your VPS
```bash
ssh username@your-vps-ip -p your-ssh-port
```

### 2. Create SSH Directory (if needed)
```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
```

### 3. Create or Edit SSH Config File
```bash
nano ~/.ssh/config
```

Add the following configuration:
```
Host github.com
    HostName github.com
    IdentityFile ~/.ssh/github_key
    User git
```

Save and exit (Ctrl+X, then Y, then Enter).

### 4. Create the GitHub SSH Key File
```bash
nano ~/.ssh/github_key
```

Paste your private SSH key that corresponds to the public key you added to GitHub.
(This is the private key that pairs with your public key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGA3Q+guuLCIe1g/q5E1LH/tKWl1uLjGXFNyBUFfsS7L zach@seezed.net`)

Save and exit (Ctrl+X, then Y, then Enter).

### 5. Set Proper Permissions
```bash
chmod 600 ~/.ssh/github_key
```

### 6. Test the GitHub Connection
```bash
ssh -T git@github.com
```

You should see a message like: "Hi username! You've successfully authenticated, but GitHub does not provide shell access."

### 7. Clone Your Repository (if needed)
```bash
git clone git@github.com:zachflem/serversetup.git
```

### 8. Configure Git User Information (if needed)
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## Troubleshooting

If you encounter any issues:

1. Verify that the SSH key is correctly added to your GitHub account
2. Check SSH key permissions (should be 600 for private key)
3. Ensure the SSH agent is running:
   ```bash
   eval "$(ssh-agent -s)"
   ssh-add ~/.ssh/github_key
   ```
4. Check SSH connection with verbose output:
   ```bash
   ssh -vT git@github.com
   ```
5. Verify that your repository's remote URL uses SSH format:
   ```bash
   git remote -v
   ```
   It should look like: `git@github.com:username/repo.git`

   If it uses HTTPS, change it to SSH:
   ```bash
   git remote set-url origin git@github.com:username/repo.git
