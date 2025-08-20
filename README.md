My ToolBox: The All-in-One Desktop Utility Suite
A versatile, cross-platform desktop application built with Python and Tkinter, providing a powerful collection of modular tools for developers, security enthusiasts, and power users in a single, convenient interface.
Problem it Solves / Motivation
In our daily digital lives, we often rely on a multitude of small, single-purpose applications for tasks like network scanning, data conversion, or file management. This leads to a cluttered workspace and the hassle of finding, installing, and managing many different programs.
My ToolBox was created to solve this problem by providing a centralized, lightweight, and extensible platform for a wide range of common and specialized utilities. It's a digital Swiss Army knife designed to boost productivity and streamline your workflow.
Key Features
The application features a main menu from which you can launch any of the following standalone tools:
Cybersecurity & Networking
network_mapper.py: Discover devices on your network, scan for open ports, and identify running services.
password_generator.py: Create strong, secure, and customizable random passwords.
steganography_tool.py: Hide secret text messages inside image files and extract them back out.
text_encryptor.py: Encrypt and decrypt text or files using strong AES encryption to protect sensitive data.
System & File Utilities
disk_visualizer.py: Scan a drive or folder and display an interactive treemap to see what's taking up your disk space.
file_renamer.py: Rename large numbers of files at once using powerful rules and patterns with a live preview.
Data & Productivity
color_picker.py: An eyedropper tool to pick any color from your screen and get its HEX, RGB, and HSL values.
graph_analyzer.py: A utility for visualizing and analyzing graph data structures.
qr_tool.py: Generate QR codes from text or URLs, and read QR codes from image files.
text_counter.py: Instantly count the characters, words, and lines in a block of text.
text_formatter.py: A utility to clean up, format, or transform text (e.g., JSON/YAML prettifying).
unit_converter.py: A simple tool to convert between various units of measurement.
dataset_finder.py: A specialized tool to help locate public datasets for research and machine learning.
research_finder.py: An assistant tool to aid in searching and organizing research materials.
Technologies Used
Language: Python 3
GUI Framework: Tkinter (via the tkinter.ttk themed widgets)
Key Libraries:
psutil: For system information and network auto-detection.
scapy: For advanced network scanning and packet crafting.
matplotlib & squarify: For data visualization in the Disk Visualizer.
Pillow (PIL): For image manipulation in the Steganography and QR Code tools.
cryptography: For strong, industry-standard encryption.
qrcode: For generating QR codes.
requests: For any tools that interact with web APIs.
Installation Instructions
Follow these steps to get the project running on your local machine.
Clone the repository:
code
Bash
git clone https://github.com/your-username/my-toolbox.git
cd my-toolbox
Create and activate a virtual environment (recommended):
code
Bash
# On Windows
python -m venv venv
.\venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
Install the required dependencies:
A requirements.txt file is included with all necessary libraries.
code
Bash
pip install -r requirements.txt
Usage Instructions
Once the installation is complete, you can run the main application from the root directory of the project.
Launch the application:
code
Bash
python main.py
The main menu will appear, displaying a button for each available tool.
Click on any button (e.g., "Network Mapper") to launch that specific tool in the application window.
Use the "Back to Menu" button within each tool to return to the main selection screen.
Conclusion / Future Scope
My ToolBox aims to be a continuously evolving suite of high-quality utilities. The modular architecture makes it easy to add new tools without affecting the core application.
Future plans include adding more powerful tools to each category, such as:
A Duplicate File Finder to reclaim wasted disk space.
A System Information Dashboard to provide a real-time overview of hardware performance.
A Clipboard History Manager to boost productivity.
A Static Malware Analyzer for basic security forensics.
Contributions and suggestions for new tools are always welcome
