<p align='center'>
<img src="/diffrays/static/images/logo-dark.png" width=60% >
<picture>
  <source srcset="/diffrays/static/images/logo-dark.png" media="(prefers-color-scheme: dark)" width=60% >
  <source srcset="/diffrays/static/images/logo-light.png" media="(prefers-color-scheme: light)" wwidth=60% >
  <img src="light-image.png" alt="DiffRays Logo">
</picture>
</p>

<!--
<img align="center" src="https://img.shields.io/github/stars/pwnfuzz/DiffRays?style=for-the-badge">
<img align="center" src="https://img.shields.io/github/forks/pwnfuzz/DiffRays?style=for-the-badge">
-->

# DiffRays - IDA Pro Binary Diffing Engine

DiffRays is a research-oriented tool for **binary patch diffing**, designed to aid in **vulnerability research, exploit development, and reverse engineering**. It leverages **IDA Pro** and the **IDA Domain API** to extract pseudocode of functions and perform structured diffing between patched and unpatched binaries.

---

## ✨ Features

- 🔎 **Patch Diffing**: Compare functions across different binary versions to identify code changes.  
- 🧩 **IDA Pro Integration**: Uses IDA Pro and the IDA Domain API for accurate pseudocode extraction.  
- 📂 **SQLite Output**: Stores results in a SQLite database for easy reuse and analysis.  
- 🌐 **Web Interface**: Built-in server mode to browse, search, and visualize diff results interactively.  
- 📊 **Research-Ready**: Designed to support vulnerability research and exploit development workflows.  

---

## 🛠️ Requirements

- [IDA Pro Version](https://hex-rays.com/ida-pro/)  
    - The IDA Domain library requires IDA Pro 9.1.0 or later.
- [IDA Domain API](https://github.com/HexRaysSA/ida-domain)  
- Python 3.8+  
- Additional Python dependencies 

---

## ⚙️ Setup

1. **Clone the repository**  
    ```bash
   git clone https://github.com/pwnfuzz/diffrays
   cd diffrays
    ```

2. **Install dependencies**  
    ```bash
    pip install .
    ```

3. **Setup IDADIR environment variable to point to your IDA installation directory:**  

    ```bash
    Windows:
        set IDADIR="[IDA Installation Directory]"

    Linux:
        export IDADIR="[IDA Installation Directory]"
    ```

---

## 🚀 Usage

```bash
> diffrays --help

______ _  __  ________
|  _  (_)/ _|/ _| ___ \
| | | |_| |_| |_| |_/ /__ _ _   _ ___
| | | | |  _|  _|    // _` | | | / __|
| |/ /| | | | | | |\ \ (_| | |_| \__ \
|___/ |_|_| |_| \_| \_\__,_|\__, |___/
                             __/ |
                            |___/      v1.0 Kappa

usage: diffrays [-h] {diff,server} ...

Binary Diff Analysis Tool - Decompile, Compare, and Visualize Binary Changes

positional arguments:
  {diff,server}  Command to execute
    diff         Analyze two binaries and generate differential database 
    server       Launch web server to view diff results

options:
  -h, --help     show this help message and exit

Examples:
  diffrays diff old_binary.exe new_binary.exe
  diffrays diff old.so new.so -o custom_name.sqlite --log
  diffrays server --db-path result_old_new_20231201.sqlite --debug

For more information, visit: https://github.com/pwnfuzz/diffrays

```

1. **Run Patch Diffing in IDA**  
Load your binaries in IDA and run DiffRays to generate diff results:  
    ```bash
    python diffrays.py diff <path_to_old_binary> <path_to_new_binary>
    ```

2. **Start the DiffRays Server**  
Once you have a .sqlite file, launch the web interface to explore the diffs:  
    ```bash
    python diffrays.py server --db-path diff_results.sqlite
    ```
    Open your browser at http://localhost:5555 to view results.

---

## 🔬 Example Workflow - Diffing CVE-2025-29824

1. **Collect target binaries**  
   - CVE-2025-1246 affects the **Common Log File System driver (`Clfs.sys`)**.  
   - Download the two versions of the driver from Microsoft’s update packages (via WinBIndex or your preferred source):  
     - Vulnerable build: **Clfs.sys 10.0.22621.5037** → [download here](https://msdl.microsoft.com/download/symbols/clfs.sys/4A2750956f000/clfs.sys)  
     - Patched build: **Clfs.sys 10.0.22621.5189** → [download here](https://msdl.microsoft.com/download/symbols/clfs.sys/68C175656f000/clfs.sys)  
   - Save them into a working directory:
    ```bash
    curl -L -o clfs_10.0.22621.5037.sys https://msdl.microsoft.com/download/symbols/clfs.sys/4A2750956f000/clfs.sys
    curl -L -o clfs_10.0.22621.5189.sys https://msdl.microsoft.com/download/symbols/clfs.sys/68C175656f000/clfs.sys
    ```

2. **Run DiffRays**  
    ```bash
    python diffrays.py diff clfs_10.0.22621.5037.sys clfs_10.0.22621.5189.sys
    ```

3. **Start the web server**
    ```bash
    python diffrays.py server --db-path clfs_diff.sqlite
    ```

4. **Browse interactively**
	- Open http://127.0.0.1:5555
	<br>
	<img src="/diffrays/static/sample/dashboard.png">

5. **Browse Diff Results**
	- The Diff Result page shows the results of binary diffing and can be sorted based on changes.
	<br>
	<img src="/diffrays/static/sample/diff.png">

6. **View Function Details**
	- Clicking on a function displays the detailed diff result.
	<br>
	<img src="/diffrays/static/sample/result.png">

---

## 📖 Use Cases

- Researching Microsoft Patch Tuesday vulnerabilities
- Identifying security fixes introduced in new software versions
- Supporting exploit development by analyzing patched vs. unpatched code paths
- Reverse engineering software updates

---

## 💡 Inspired By

DiffRays takes inspiration from prior research and tools in the binary diffing space, including:

- [BinDiff](https://github.com/google/bindiff) - Quickly find differences and similarities in disassembled code.
- [Diaphora](https://github.com/joxeankoret/diaphoraDiaphora) - Diaphora, the most advanced Free and Open Source program diffing tool.
- [Ghidriff](https://github.com/clearbluejar/ghidriff) - Python Command-Line Ghidra Binary Diffing Engine

---

## ⚠️ Disclaimer

This project is intended for educational and research purposes only.
The author does not condone or encourage malicious use of this tool.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/pwnfuzz/DiffRays/blob/main/LICENSE) file for details.
