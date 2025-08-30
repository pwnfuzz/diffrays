<p align='center'>
<img src="" width=60% >
</p>

<img align="center" src="https://img.shields.io/github/stars/pwnfuzz/DiffRays?style=for-the-badge">
<img align="center" src="https://img.shields.io/github/forks/pwnfuzz/DiffRays?style=for-the-badge">

# DiffRays - IDA Pro Binary Diffing Engine

DiffRays is a research-oriented tool for **binary patch diffing**, designed to aid in **vulnerability research, exploit development, and reverse engineering**. It leverages **IDA Pro** and the **IDA Domain API** to extract pseudocode of functions and perform structured diffing between patched and unpatched binaries.

---

## ✨ Features

- 🔎 **Patch Diffing**: Compare functions across different binary versions to identify code changes.  
- 🧩 **IDA Pro Integration**: Uses IDA Pro and the IDA Domain API for pseudocode extraction.  
- 📂 **SQLite Output**: Store results in a SQLite database for easy reuse and analysis.  
- 🌐 **Web Interface**: Built-in server mode to browse, search, and visualize diff results interactively.  
- 📊 **Research-Ready**: Designed to support vulnerability research and exploit development workflows.  

---

## 🛠️ Requirements

- [IDA Pro Version](https://hex-rays.com/ida-pro/)  
    - The IDA Domain library requires IDA Pro 9.1.0 or later.
- [IDA Domain API](https://github.com/HexRaysSA/ida-domain)  
- Python 3.8+  
- Additional Python dependencies (listed in `requirements.txt`)  

---

## ⚙️ Setup

1. **Clone the repository**  
    ```bash
   git clone https://github.com/pwnfuzz/DiffRays
   cd diffrays
    ```

2. **Install dependencies**  
    ```bash
    pip install -r requirements.txt
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
Open http://127.0.0.1:5555

<IMG>ADD HERE</IMG>

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

This project is intended for educational and research purposes only. The author does not condone or encourage malicious use of this tool.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/pwnfuzz/DiffRays/blob/main/LICENSE) file for details.
