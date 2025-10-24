# Data-Redundancy-Removal-System

This is the repository for the Data Redundancy Removal System, a project designed to save storage space by instantly detecting and preventing duplicate files from being stored.

# How It Works (The Core Idea)

This application prevents users from uploading the same file twice, even if they rename it.

# Digital Fingerprint:
When a file is uploaded, the system calculates a unique digital fingerprint using the SHA-256 Checksum algorithm.

# Instant Check:
This fingerprint is checked against all existing files in the database.

# No Duplicates:

If the file is unique, it is stored normally.

If the file is a duplicate, the system blocks the physical storage and just records a pointer to the original file.

This core logic ensures maximum storage efficiency.

 # Technology Used

This implementation proves the core deduplication logic using a local setup that is ready for future cloud deployment.

Backend: Python (Flask)

Database: MySQL

Frontend: HTML/CSS (Used for user pages, file upload, and management)

# Key Features

Secure Authentication: User Login, Registration, and Password Reset.

Efficient Deduplication: Instant duplicate detection using SHA-256.

File Management: Users can Upload, View, Download, and Delete their stored files.

# Getting Started

1. Clone this repository.

2. Install Python dependencies: pip install Flask mysql-connector-python Werkzeug smtplib itsdangerous

3. Set up your local MySQL database with tables for users and files.

4. Run the main application file (e.g., python app.py).
