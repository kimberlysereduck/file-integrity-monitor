Secure Folder Test Fixture

This folder contains harmless sample text files for testing the file integrity
monitor. Create a baseline with:

    python monitor.py secure_folder --baseline

Then start monitoring with:

    python monitor.py secure_folder --monitor

While monitoring, edit, add, or remove a file in this folder to test alerts.
