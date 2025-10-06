# Nginx Configuration Issue - Explanation and Fix

## What Happened

When your server setup script ran, it encountered an error during the Nginx configuration phase. The specific error was:

```
2025/10/06 08:14:12 [emerg] 11714#11714: a duplicate default server for 0.0.0.0:80 in /etc/nginx/sites-enabled/default:22
nginx: configuration file /etc/nginx/nginx.conf test failed
```

### Root Cause Analysis

This error occurs because of a **duplicate default server configuration**. In Nginx, only one server block can be designated as the default server for a given IP address and port combination. In this case, there were two server blocks both trying to be the default for port 80:

1. The first default server was in `/etc/nginx/sites-enabled/default` - This is the default site configuration that comes with Nginx when installed on Ubuntu/Debian systems
2. The second default server was in `/etc/nginx/conf.d/default.conf` - This is the custom configuration created by your server setup script

When Nginx tried to validate the configuration with `nginx -t`, it detected this conflict and failed.

## The Fix

I've updated your `server_setup.sh` script to fix this issue. The fix is straightforward but important:

```bash
# Remove the default site configuration to avoid conflicts
if [ -f /etc/nginx/sites-enabled/default ]; then
    rm /etc/nginx/sites-enabled/default
    info "Removed default Nginx site configuration to prevent conflicts."
fi
```

This code does the following:

1. Checks if the default site configuration file exists at `/etc/nginx/sites-enabled/default`
2. If it exists, removes it to prevent the conflict
3. Logs a message indicating the action taken

## Why This Works

Nginx loads configuration from several locations, primarily:

- `/etc/nginx/nginx.conf` - The main configuration file
- `/etc/nginx/sites-enabled/` - Directory containing enabled site configurations 
- `/etc/nginx/conf.d/` - Directory containing additional configurations

The order of loading means that configurations can potentially conflict. By removing the default site configuration before adding our custom one, we ensure there's only one default server configuration for port 80.

## For Future Reference

When working with Nginx, keep these points in mind:

1. You can only have one default server per IP:port combination
2. The `default_server` parameter in the `listen` directive designates a server block as the default
3. If no server block has `default_server` explicitly set, the first server block for that IP:port becomes the default
4. Nginx's configuration can span multiple files across several directories, which can lead to conflicts

## Manual Fix (If Needed)

If you encounter this issue again on a live server, you can manually fix it with these steps:

1. Identify the conflicting configurations:
   ```bash
   grep -r "default_server" /etc/nginx/
   ```

2. Choose which configuration to keep and which to remove or modify

3. Either:
   - Remove one configuration: `rm /etc/nginx/sites-enabled/default`
   - Or edit to remove the `default_server` directive from one of them

4. Test and reload Nginx:
   ```bash
   nginx -t
   systemctl reload nginx
   ```

The updated script should now run without Nginx configuration errors.
