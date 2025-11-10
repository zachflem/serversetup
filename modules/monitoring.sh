#!/bin/bash

# Source required files
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/functions.sh"
source "$SCRIPT_DIR/system_ops.sh"

#############################################################
# System Monitoring Functions
#############################################################

# Configure system monitoring tools
setup_monitoring() {
    info "Setting up system monitoring..."
    
    # Install monitoring packages
    local monitoring_packages=(
        "prometheus-node-exporter"
        "netdata"
        "htop"
        "iotop"
        "sysstat"
        "nmon"
    )
    
    install_packages "${monitoring_packages[@]}"
    
    # Configure monitoring services
    configure_node_exporter
    configure_netdata
    configure_sysstat
    
    success "System monitoring setup completed"
}

# Configure Prometheus Node Exporter
configure_node_exporter() {
    info "Configuring Prometheus Node Exporter..."
    
    # Create service override directory
    mkdir -p /etc/systemd/system/prometheus-node-exporter.service.d
    
    # Configure service with additional options
    cat > /etc/systemd/system/prometheus-node-exporter.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter \
    --collector.diskstats \
    --collector.filesystem \
    --collector.loadavg \
    --collector.meminfo \
    --collector.netdev \
    --collector.stat \
    --collector.vmstat \
    --collector.systemd
EOF
    
    # Reload systemd and restart service
    systemctl daemon-reload
    configure_service prometheus-node-exporter restart
    configure_service prometheus-node-exporter enable
    
    success "Prometheus Node Exporter configured"
}

# Configure Netdata monitoring
configure_netdata() {
    info "Configuring Netdata..."
    
    # Create Netdata configuration directory
    mkdir -p /etc/netdata
    
    # Configure Netdata
    cat > /etc/netdata/netdata.conf << EOF
[global]
    memory mode = dbengine
    page cache size = 32
    dbengine disk space = 256

[web]
    mode = static-threaded
    bind to = localhost
    port = 19999

[plugins]
    proc = yes
    diskspace = yes
    cgroups = yes
    tc = yes
    idlejitter = yes
    python.d = yes
    apps = yes
    charts.d = yes
EOF
    
    # Configure retention
    cat > /etc/netdata/stream.conf << EOF
[stream]
    enabled = no
    destination = none
    api key = 
    timeout seconds = 60
    default port = 19999
    buffer size bytes = 1048576
    reconnect delay seconds = 5
    initial clock resync iterations = 60
EOF
    
    # Restart Netdata
    configure_service netdata restart
    configure_service netdata enable
    
    success "Netdata configured"
}

# Configure system statistics collection
configure_sysstat() {
    info "Configuring system statistics collection..."
    
    # Configure sysstat
    cat > /etc/default/sysstat << EOF
ENABLED="true"
HISTORY=28
COMPRESSAFTER=10
SADC_OPTIONS="-S DISK"
EOF
    
    # Configure collection frequency
    cat > /etc/cron.d/sysstat << EOF
# Activity reports every 10 minutes everyday
*/10 * * * * root command -v sa1 > /dev/null && sa1 1 1
# Daily summary prepared at 23:53
53 23 * * * root command -v sa2 > /dev/null && sa2 -A
EOF
    
    # Start sysstat service
    configure_service sysstat restart
    configure_service sysstat enable
    
    success "System statistics collection configured"
}

#############################################################
# Logging Functions
#############################################################

# Configure centralized logging
setup_logging() {
    info "Setting up centralized logging..."
    
    # Install logging packages
    local logging_packages=(
        "rsyslog"
        "logrotate"
        "logwatch"
        "fail2ban"
    )
    
    install_packages "${logging_packages[@]}"
    
    # Configure logging services
    configure_rsyslog
    configure_logrotate
    configure_logwatch
    
    success "Centralized logging setup completed"
}

# Configure rsyslog
configure_rsyslog() {
    info "Configuring rsyslog..."
    
    # Create log directories
    mkdir -p /var/log/custom
    
    # Configure rsyslog
    cat > /etc/rsyslog.d/custom.conf << EOF
# Custom logging rules
local0.*                        /var/log/custom/applications.log
local1.*                        /var/log/custom/security.log
local2.*                        /var/log/custom/performance.log

# Docker container logs
if \$programname startswith 'docker' then /var/log/custom/docker.log
& stop

# High priority messages
*.err;*.crit;*.alert;*.emerg   /var/log/custom/critical.log
& stop
EOF
    
    # Set permissions
    chmod 644 /etc/rsyslog.d/custom.conf
    chown -R root:root /var/log/custom
    
    # Restart rsyslog
    configure_service rsyslog restart
    
    success "Rsyslog configured"
}

# Configure log rotation
configure_logrotate() {
    info "Configuring log rotation..."
    
    # Configure custom log rotation
    cat > /etc/logrotate.d/custom << EOF
/var/log/custom/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
    
    # Configure Docker log rotation
    cat > /etc/logrotate.d/docker << EOF
/var/lib/docker/containers/*/*.log {
    rotate 7
    daily
    compress
    size=50M
    missingok
    delaycompress
    copytruncate
}
EOF
    
    success "Log rotation configured"
}

# Configure logwatch
configure_logwatch() {
    info "Configuring logwatch..."
    
    # Create logwatch configuration directory
    mkdir -p /etc/logwatch/conf
    
    # Configure logwatch
    cat > /etc/logwatch/conf/logwatch.conf << EOF
LogDir = /var/log
TmpDir = /var/cache/logwatch
Output = mail
Format = html
Encode = none
MailTo = root
Range = yesterday
Detail = Medium
Service = All
mailer = "/usr/sbin/sendmail -t"
EOF
    
    # Create daily report script
    cat > /etc/cron.daily/00logwatch << EOF
#!/bin/bash
/usr/sbin/logwatch --output mail
EOF
    
    chmod +x /etc/cron.daily/00logwatch
    
    success "Logwatch configured"
}

#############################################################
# Performance Monitoring Functions
#############################################################

# Monitor system resources
monitor_resources() {
    info "Monitoring system resources..."
    
    # CPU usage
    echo "CPU Usage:"
    top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}'
    
    # Memory usage
    echo "Memory Usage:"
    free -m | awk 'NR==2{printf "%.2f%%\n", $3*100/$2}'
    
    # Disk usage
    echo "Disk Usage:"
    df -h / | awk 'NR==2{print $5}'
    
    # Load average
    echo "Load Average:"
    uptime | awk -F'[a-z]:' '{ print $2}'
}

# Monitor Docker resources
monitor_docker() {
    info "Monitoring Docker resources..."
    
    # List running containers
    echo "Running Containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.CPUPerc}}\t{{.MemUsage}}"
    
    # Check Docker daemon status
    echo "Docker Daemon Status:"
    systemctl status docker --no-pager | grep "Active:"
}

# Monitor network connections
monitor_network() {
    info "Monitoring network connections..."
    
    # Active connections
    echo "Active Connections:"
    netstat -tun | grep ESTABLISHED | wc -l
    
    # Listening ports
    echo "Listening Ports:"
    netstat -tlnp
}

# Generate system health report
generate_health_report() {
    local report_file="/var/log/custom/health_report_$(date +%Y%m%d).txt"
    
    info "Generating system health report..."
    
    {
        echo "System Health Report - $(date)"
        echo "============================"
        echo
        
        echo "System Information:"
        echo "---------------"
        uname -a
        echo
        
        echo "Resource Usage:"
        echo "-------------"
        monitor_resources
        echo
        
        echo "Docker Status:"
        echo "-------------"
        monitor_docker
        echo
        
        echo "Network Status:"
        echo "--------------"
        monitor_network
        echo
        
        echo "Recent Critical Logs:"
        echo "------------------"
        tail -n 50 /var/log/custom/critical.log
        
    } > "$report_file"
    
    success "Health report generated: $report_file"
}

# Monitor specific service
monitor_service() {
    local service="$1"
    
    info "Monitoring service: $service"
    
    # Check service status
    systemctl status "$service" --no-pager
    
    # Check service logs
    journalctl -u "$service" --no-pager -n 50
    
    # Check resource usage
    ps aux | grep "$service" | grep -v grep
}

# Setup monitoring alerts
setup_alerts() {
    local email="$1"
    
    info "Setting up monitoring alerts..."
    
    # Create alert script
    cat > /usr/local/bin/system-alert << EOF
#!/bin/bash

# Check CPU usage
cpu_usage=\$(top -bn1 | grep "Cpu(s)" | awk '{print \$2 + \$4}')
if (( \$(echo "\$cpu_usage > 90" | bc -l) )); then
    echo "High CPU usage: \$cpu_usage%" | mail -s "CPU Alert" "$email"
fi

# Check memory usage
mem_usage=\$(free -m | awk 'NR==2{printf "%.2f", \$3*100/\$2}')
if (( \$(echo "\$mem_usage > 90" | bc -l) )); then
    echo "High memory usage: \$mem_usage%" | mail -s "Memory Alert" "$email"
fi

# Check disk usage
disk_usage=\$(df -h / | awk 'NR==2{print \$5}' | sed 's/%//')
if (( disk_usage > 90 )); then
    echo "High disk usage: \$disk_usage%" | mail -s "Disk Alert" "$email"
fi
EOF
    
    chmod +x /usr/local/bin/system-alert
    
    # Create cron job for alerts
    echo "*/5 * * * * root /usr/local/bin/system-alert" > /etc/cron.d/system-alerts
    
    success "Monitoring alerts configured"
}
