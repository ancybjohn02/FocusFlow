<!-- make the setup code executable -->
chmod +x setup_activity_tracker.sh

<!-- run the script -->
./setup_activity_tracker.sh

Target OS,Action,Command

* Windows,Run the following command on a Windows machine:,pyinstaller --onefile tracker.py
* Linux,Run the following command on a Linux machine:,pyinstaller --onefile tracker.py
* macOS,Run the following command on a macOS machine:,pyinstaller --onefile --windowed tracker.py
