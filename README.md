# My Toolbox

## Introduction

My Toolbox is a comprehensive Python-based desktop utility framework built with Tkinter. It bundles a collection of independent tools into one modern graphical interface. These tools cover a wide range of functionality, including text manipulation (formatting, counting, encrypting), unit conversion, QR code generation and scanning, password generation, graph analysis, steganography, network scanning, research finding, dataset discovery, color picking, and more. Each tool is organized as a separate module and can be accessed from a main menu that offers intuitive navigation through various functionalities.

## Requirements

- **Python Version:** 3.7 or higher  
- **GUI Framework:** Tkinter (included with standard Python distributions)  
- **Additional Libraries:**  
  - cryptography  
  - pyperclip  
  - Pillow  
  - reportlab  
  - networkx  
  - matplotlib  
  - scipy  
  - qrcode  
  - pyzbar  
  - requests  
  - ddgs  
- **Operating System:** Cross-platform (Windows, macOS, Linux)  
- **Others:** Ensure required dependencies are installed by using pip.

## Features

- **Multi-tool Interface:**  
  A centralized GUI that integrates various independent tools.
  
- **Unit Converter:**  
  Convert values between different units including length, weight, and temperature.
  
- **Text Formatter:**  
  Convert plain text to PDF or Markdown with easy-to-use options.
  
- **Text Encryptor/Decryptor:**  
  Encrypt or decrypt textual data using secure cryptographic methods.
  
- **Password Generator:**  
  Create secure passwords with customizable options for length and character sets.
  
- **QR Code Tools:**  
  Generate and scan QR codes with support for saving output.
  
- **Graph Analyzer:**  
  Load graph files, compute metrics, perform clustering, and visualize networks.
  
- **Network Security Scanner:**  
  Discover live hosts and scan for open ports with detailed logging.
  
- **Dataset and Research Finder:**  
  Search for datasets and research papers from multiple sources.
  
- **Steganography:**  
  Encode and decode messages within images.
  
- **Color Picker:**  
  Choose and manage colors from a graphical interface.

## Usage

1. **Run the Application:**  
   Open a terminal or command prompt and execute the following command:
   ```
   python main.py
   ```
   The main window will appear displaying the tool menu with icons and names.

2. **Select a Tool:**  
   Click on the appropriate icon and label corresponding to the tool you wish to use. Each tool opens a dedicated panel where you can input data and adjust settings.

3. **Interact with the Tool Interface:**  
   - Input your data in text boxes or selection fields.
   - Use provided buttons and sliders to execute tool actions.
   - Output, results, or generated files appear directly in the UI.
   
4. **Saving and Exporting:**  
   Some tools allow you to save results (e.g., PDF export, QR output, or file renaming logs) automatically in a designated results folder.

## Configuration

The application provides minimal configuration to ensure ease of use. However, you may customize the following:

- **Results Folder:**  
  The base folder for saving tool outputs is defined in the utilities and can be modified by changing the value of `RESULTS_ROOT` in the utilities module.

- **Tool Options:**  
  Individual tools offer options to customize their behavior, such as selecting conversion types, password parameters, or graph file formats.

- **Theme Customization:**  
  The visual appearance is governed by a dedicated theme module. Adjust colors, fonts, and button styles within the theme file as needed.

## Contributing

Contributions are welcome! To help improve My Toolbox:

- **Fork the Repository:**  
  Create a fork and clone it to your local machine.

- **Create Branches:**  
  Work on a new feature or fix and create a separate branch.

- **Submit Pull Requests:**  
  Once changes are made, submit a pull request with your detailed description of improvements or bug fixes.

- **Report Issues:**  
  Use the issue tracker on the repository to report bugs or request new features.

Be sure to follow the existing code style and documentation guidelines when contributing.

## Installation

1. **Clone the Repository:**
   ```
   git clone https://github.com/RegalNexian/My_ToolBox.git
   cd My_ToolBox
   ```

2. **Create a Virtual Environment (optional but recommended):**
   ```
   python -m venv venv
   source venv/bin/activate    # On Windows use: venv\Scripts\activate
   ```

3. **Install Dependencies:**  
   If a requirements file is provided, run:
   ```
   pip install -r requirements.txt
   ```
   Otherwise, install the required libraries individually using pip:
   ```
   pip install cryptography pyperclip Pillow reportlab networkx matplotlib scipy qrcode pyzbar requests ddgs
   ```

4. **Run the Application:**
   ```
   python main.py
   ```

## License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) [Year] [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

Enjoy using My Toolbox and feel free to contribute improvements or report any issues you encounter!