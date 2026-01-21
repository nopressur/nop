#!/bin/bash
# This file is part of the product NoPressure.
# SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
# SPDX-License-Identifier: AGPL-3.0-or-later
# The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.


# nop process management script
# Usage: _nop.sh {start|stop|status|restart}

# Configuration - use current directory
NOP_DIR="$(pwd)"
NOP_BINARY="./nop"
NOP_LOG_DIR="$NOP_DIR/logs"
NOP_LOG_FILE="$NOP_LOG_DIR/nop.log"
NOP_PID_FILE="$NOP_DIR/nop.pid"

# Ensure log directory exists
mkdir -p "$NOP_LOG_DIR"

# Function to check if nop is running
is_nop_running() {
    if [ -f "$NOP_PID_FILE" ]; then
        local pid=$(cat "$NOP_PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            # Verify it's actually nop process
            if ps -p "$pid" -o comm= | grep -q "nop"; then
                return 0
            else
                # PID file exists but process is not nop, remove stale PID file
                rm -f "$NOP_PID_FILE"
                return 1
            fi
        else
            # PID file exists but process is not running, remove stale PID file
            rm -f "$NOP_PID_FILE"
            return 1
        fi
    else
        # Also check by process name in case PID file is missing
        # Use more specific pattern to avoid matching this script or pgrep itself
        pgrep -f "^\./nop$" > /dev/null 2>&1
        return $?
    fi
}

# Function to rotate logs
rotate_logs() {
    if [ -f "$NOP_LOG_FILE" ]; then
        echo "Rotating logs..."
        
        # Remove oldest gzipped log if it exists
        [ -f "$NOP_LOG_FILE.10.gz" ] && rm -f "$NOP_LOG_FILE.10.gz"
        
        # Rotate gzipped logs (8 -> 9, 7 -> 8, etc.)
        for i in $(seq 9 -1 3); do
            prev=$((i-1))
            [ -f "$NOP_LOG_FILE.$prev.gz" ] && mv "$NOP_LOG_FILE.$prev.gz" "$NOP_LOG_FILE.$i.gz"
        done
        
        # Compress and rotate the second uncompressed log
        [ -f "$NOP_LOG_FILE.2" ] && gzip -c "$NOP_LOG_FILE.2" > "$NOP_LOG_FILE.3.gz" && rm -f "$NOP_LOG_FILE.2"
        
        # Rotate uncompressed logs (1 -> 2, current -> 1)
        [ -f "$NOP_LOG_FILE.1" ] && mv "$NOP_LOG_FILE.1" "$NOP_LOG_FILE.2"
        [ -f "$NOP_LOG_FILE" ] && mv "$NOP_LOG_FILE" "$NOP_LOG_FILE.1"
        
        echo "Log rotation completed."
    fi
}

# Function to start nop
start_nop() {
    if is_nop_running; then
        echo "nop is already running (PID: $(cat "$NOP_PID_FILE" 2>/dev/null || pgrep -f "nop"))"
        return 1
    fi
    
    echo "Starting nop..."
    
    # Rotate logs before starting
    rotate_logs
    
    # Check if binary exists in current directory
    if [ ! -f "$NOP_BINARY" ]; then
        echo "Error: nop binary not found in current directory: $NOP_BINARY"
        echo "Make sure the nop binary is in the current directory"
        return 1
    fi
    
    # Start nop with nohup, redirecting output to log file
    nohup "$NOP_BINARY" -F > "$NOP_LOG_FILE" 2>&1 &
    local nop_pid=$!
    
    # Save PID to file
    echo $nop_pid > "$NOP_PID_FILE"
    
    # Give it a moment to start
    sleep 2
    
    # Verify it started successfully
    if is_nop_running; then
        echo "nop started successfully (PID: $nop_pid)"
        echo "Logs are being written to: $NOP_LOG_FILE"
        return 0
    else
        echo "Failed to start nop"
        rm -f "$NOP_PID_FILE"
        return 1
    fi
}

# Function to stop nop
stop_nop() {
    if ! is_nop_running; then
        echo "nop is not running"
        return 1
    fi
    
    local pid
    if [ -f "$NOP_PID_FILE" ]; then
        pid=$(cat "$NOP_PID_FILE")
    else
        pid=$(pgrep -f "^\./nop$")
    fi
    
    echo "Stopping nop (PID: $pid)..."
    
    # Try graceful shutdown first
    kill "$pid"
    
    # Wait up to 10 seconds for graceful shutdown
    local count=0
    while [ $count -lt 10 ] && is_nop_running; do
        sleep 1
        count=$((count + 1))
    done
    
    # If still running, force kill
    if is_nop_running; then
        echo "Process did not stop gracefully, forcing shutdown..."
        kill -9 "$pid"
        sleep 1
    fi
    
    # Clean up PID file
    rm -f "$NOP_PID_FILE"
    
    if is_nop_running; then
        echo "Failed to stop nop"
        return 1
    else
        echo "nop stopped successfully"
        return 0
    fi
}

# Function to show status
status_nop() {
    if is_nop_running; then
        local pid
        if [ -f "$NOP_PID_FILE" ]; then
            pid=$(cat "$NOP_PID_FILE")
        else
            pid=$(pgrep -f "^\./nop$")
        fi
        echo "nop is running (PID: $pid)"
        return 0
    else
        echo "nop is not running"
        return 1
    fi
}

# Function to restart nop
restart_nop() {
    echo "Restarting nop..."
    stop_nop
    sleep 2
    start_nop
}

# Main script logic
case "$1" in
    start)
        start_nop
        ;;
    stop)
        stop_nop
        ;;
    status)
        status_nop
        ;;
    restart)
        restart_nop
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        echo ""
        echo "Commands:"
        echo "  start   - Start nop process (if not already running)"
        echo "  stop    - Stop nop process (if running)"
        echo "  status  - Check if nop is running"
        echo "  restart - Stop and start nop process"
        echo ""
        echo "Logs are stored in: $NOP_LOG_DIR"
        exit 1
        ;;
esac

exit $? 
