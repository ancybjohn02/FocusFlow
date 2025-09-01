echo "Setting up Activity Tracker..."

# Install Python dependencies
pip install psutil watchdog scapy

# Install system dependencies based on OS
if command -v apt-get > /dev/null; then
    echo "Installing xdotool for Ubuntu/Debian..."
    sudo apt-get update
    sudo apt-get install -y xdotool
elif command -v dnf > /dev/null; then
    echo "Installing xdotool for Fedora/RHEL..."
    sudo dnf install -y xdotool
elif command -v pacman > /dev/null; then
    echo "Installing xdotool for Arch Linux..."
    sudo pacman -S --noconfirm xdotool
fi

echo "Setup complete! Run with:"
echo "  python activity_tracker.py    (basic monitoring)"
echo "  sudo python activity_tracker.py    (full monitoring with network)"