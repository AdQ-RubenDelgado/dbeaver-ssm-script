import click
import subprocess
import psutil
import boto3
import signal
import time
from pathlib import Path
import os
from datetime import datetime

# Directories for storing PID and Session ID files
PID_DIR = Path(__file__).parent / "pids"
SESSION_DIR = Path(__file__).parent / "sessions"
PID_DIR.mkdir(exist_ok=True)
SESSION_DIR.mkdir(exist_ok=True)

# Helper function for logging
def log_message(level, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    click.echo(f"[{timestamp}] [{level}] {message}")

# Function to start an SSM session
def start_ssm_session(name, instance_id, remote_host, remote_port, local_port, aws_profile, region):
    command = [
        "aws", "ssm", "start-session",
        "--region", region,
        "--target", instance_id,
        "--document-name", "AWS-StartPortForwardingSessionToRemoteHost",
        "--parameters",
        f"host={remote_host},portNumber={remote_port},localPortNumber={local_port}",
        "--profile", aws_profile
    ]

    log_message("INFO", f"Starting SSM session '{name}' in the background ({local_port} -> {remote_host}:{remote_port})...")

    # Execute the command in the background
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Save the process PID to a file
    pid_file = PID_DIR / f"{name}.pid"
    with open(pid_file, "w") as f:
        f.write(str(process.pid))

    log_message("INFO", f"SSM session '{name}' started (PID: {process.pid})")

    # Wait a few seconds to allow the session to initialize
    time.sleep(5)

    # Check the session status using boto3
    session_id = check_session_status(instance_id, aws_profile, region)

    # Save the Session ID to a file
    if session_id:
        session_file = SESSION_DIR / f"{name}.session"
        with open(session_file, "w") as f:
            f.write(session_id)
        log_message("INFO", f"Session ID '{session_id}' saved to '{session_file}'")

# Function to check session status using boto3
def check_session_status(instance_id, aws_profile, region):
    session = boto3.Session(profile_name=aws_profile, region_name=region)
    client = session.client('ssm')

    log_message("INFO", "Checking active SSM sessions...")
    try:
        response = client.describe_sessions(
            State='Active',
            Filters=[
                {'key': 'Target', 'value': instance_id}
            ]
        )

        if response['Sessions']:
            session_id = response['Sessions'][0]['SessionId']
            status = response['Sessions'][0]['Status']
            log_message("INFO", f"Active session found: Session ID: {session_id}, Status: {status}")
            return session_id
        else:
            log_message("WARNING", "No active sessions found.")
            return None

    except Exception as e:
        log_message("ERROR", f"Failed to check session status: {e}")
        return None

# Function to get the PID
def get_pid(name):
    pid_file = PID_DIR / f"{name}.pid"
    if pid_file.exists():
        with open(pid_file, "r") as f:
            return int(f.read().strip())
    return None

# Function to get the Session ID
def get_session_id(name):
    session_file = SESSION_DIR / f"{name}.session"
    if session_file.exists():
        with open(session_file, "r") as f:
            return f.read().strip()
    return None

# Function to check if the process is still running
def is_process_running(pid):
    return psutil.pid_exists(pid)

# Function to terminate the SSM session using boto3
def terminate_session(name, aws_profile, region):
    session_id = get_session_id(name)
    if not session_id:
        log_message("WARNING", f"Session ID not found for '{name}'.")
        return

    session = boto3.Session(profile_name=aws_profile, region_name=region)
    client = session.client('ssm')

    log_message("INFO", f"Terminating SSM session with Session ID: {session_id}")
    try:
        client.terminate_session(SessionId=session_id)
        log_message("INFO", f"SSM session '{session_id}' terminated successfully.")

        # Remove the session file
        (SESSION_DIR / f"{name}.session").unlink()
        log_message("INFO", f"Session ID file for '{name}' removed.")
    except Exception as e:
        log_message("ERROR", f"Failed to terminate the session: {e}")

# Function to stop the local process
def stop_process(pid, name):
    try:
        log_message("INFO", f"Stopping local process (PID: {pid}) for session '{name}'...")
        os.kill(pid, signal.SIGINT)
        (PID_DIR / f"{name}.pid").unlink()
        log_message("INFO", f"Local process for session '{name}' stopped and PID file removed.")
    except Exception as e:
        log_message("ERROR", f"Failed to stop the local process for session '{name}': {e}")

@click.group()
def cli():
    """CLI tool for managing SSM sessions."""
    pass

@cli.command()
@click.option("--name", required=True, help="SSM session identifier.")
@click.option("--instance-id", required=True, help="EC2 instance ID.")
@click.option("--remote-host", required=True, help="Remote host (e.g., database host).")
@click.option("--remote-port", required=True, type=int, help="Remote host port.")
@click.option("--local-port", required=True, type=int, help="Local port for port forwarding.")
@click.option("--aws-profile", required=True, help="AWS profile to use.")
@click.option("--region", required=True, help="AWS region.")
def start(name, instance_id, remote_host, remote_port, local_port, aws_profile, region):
    pid = get_pid(name)
    if pid and is_process_running(pid):
        log_message("WARNING", f"Tunnel '{name}' is already running (PID: {pid}). Stopping it before starting a new session.")
        stop_process(pid, name)

    start_ssm_session(name, instance_id, remote_host, remote_port, local_port, aws_profile, region)

@cli.command()
@click.argument("name")
@click.option("--aws-profile", required=True, help="AWS profile to use.")
@click.option("--region", required=True, help="AWS region.")
def stop(name, aws_profile, region):
    pid = get_pid(name)
    if pid and is_process_running(pid):
        stop_process(pid, name)
    terminate_session(name, aws_profile, region)

@cli.command()
@click.argument("name")
def status(name):
    """Show the status of a specific SSM tunnel."""
    pid = get_pid(name)
    if pid and is_process_running(pid):
        log_message("INFO", f"SSM session '{name}' is active (PID: {pid}).")
    else:
        log_message("INFO", f"SSM session '{name}' is not active.")

if __name__ == "__main__":
    cli()
