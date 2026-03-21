# Windows Setup Guide (Python Version)

This guide will help you set up and run the Packet Analyzer on Windows. This project is now primarily Python-based.

---

## Step 1: Install Python

If you don't have Python installed:

1. Download **Python 3.10 or newer** from: [python.org](https://www.python.org/downloads/windows/)
2. Run the installer and **IMPORTANT**: Check the box that says **"Add Python to PATH"**.
3. Click "Install Now".

## Step 2: Open the Project

1. Open **Command Prompt** (cmd) or **PowerShell**.
2. Navigate to your project folder:
   ```cmd
   cd /d "D:\ALL\Study\Personal Projects\Packet_analyzer\Packet_analyzer"
   ```

## Step 3: Generate Test Data

Before running the analyzer, you need a PCAP file to test with. Run the generator script:

```cmd
python generate_test_pcap.py
```
This will create a file named `test_dpi.pcap` in the root folder.

## Step 4: Run the Analyzer

You have two versions of the analyzer available:

### Simple Version (Single-threaded)
Best for learning and small files.
```cmd
python -m src.dpi_simple test_dpi.pcap output_simple.pcap
```

### Multi-threaded Version (High Performance)
Uses multiple CPU cores for faster processing.
```cmd
python -m src.dpi_mt test_dpi.pcap output_mt.pcap --fps 4
```

## Step 5: Options and Filtering

You can block specific traffic using flags:

```cmd
# Block YouTube and a specific IP
python -m src.dpi_mt test_dpi.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
```

---

## Troubleshooting

### Error: 'python' is not recognized
**Fix:** Python is not in your PATH. Re-run the installer and check "Add Python to PATH", or add it manually in Environment Variables.

### Error: No module named 'src'
**Fix:** Ensure you are running the command from the root `packet_analyzer` folder, NOT from inside the `src` folder. Also ensure there is an `__init__.py` file in the `src` folder.

### Missing Test Data
**Fix:** Run `python generate_test_pcap.py` first.
