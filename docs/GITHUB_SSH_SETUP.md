# GitHub SSH Authentication Setup

This guide will help you set up SSH authentication for your GitHub repository.

## Add Your SSH Key to GitHub

1. **Copy Your SSH Public Key**
   Your SSH public key is:
   ```
   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGA3Q+guuLCIe1g/q5E1LH/tKWl1uLjGXFNyBUFfsS7L zach@seezed.net
   ```

2. **Add the Key to Your GitHub Account**:
   - Go to GitHub.com and sign in
   - Click on your profile icon in the top-right corner
   - Select "Settings" from the dropdown menu
   - In the left sidebar, click on "SSH and GPG keys"
   - Click the "New SSH key" button
   - Give your key a descriptive title (e.g., "Windows Development Machine")
   - Paste your SSH public key into the "Key" field
   - Click "Add SSH key"

3. **Verify SSH Connection to GitHub**:
   ```bash
   ssh -T git@github.com
   ```
   If successful, you'll see a message like: "Hi username! You've successfully authenticated, but GitHub does not provide shell access."

## Change Remote URL from HTTPS to SSH

Now that your SSH key is set up, change your repository's remote URL from HTTPS to SSH:

```bash
git remote set-url origin git@github.com:zachflem/serversetup.git
```

To verify the change:

```bash
git remote -v
```

You should see:
```
origin  git@github.com:zachflem/serversetup.git (fetch)
origin  git@github.com:zachflem/serversetup.git (push)
```

## Test Pushing Changes

After completing these steps, you can test pushing changes without entering your GitHub credentials:

1. Make a small change to a file
2. Commit the change:
   ```bash
   git add .
   git commit -m "Test SSH authentication"
   git push
   ```

The push should complete without prompting for a password.

## Troubleshooting

- If you encounter authentication issues, verify that your SSH key is added correctly to GitHub
- If you're using SSH for the first time, you might need to start the SSH agent:
  ```bash
  eval "$(ssh-agent -s)"
  ssh-add ~/.ssh/id_ed25519
  ```
- Ensure your SSH key has the correct permissions:
  ```bash
  chmod 600 ~/.ssh/id_ed25519
  chmod 644 ~/.ssh/id_ed25519.pub
