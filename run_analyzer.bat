@echo off
setlocal

:: Settings
set INPUT_PCAP=test_dpi.pcap
set OUTPUT_PCAP=output_mt.pcap
set WORKERS=4

echo ==========================================
echo       Packet Analyzer Quick Run
echo ==========================================
echo.

:: Check for input file, generate if missing
if not exist %INPUT_PCAP% (
    echo [!] %INPUT_PCAP% not found. Generating test data...
    python generate_test_pcap.py
    if errorlevel 1 (
        echo [!] Failed to generate test pcap.
        pause
        exit /b 1
    )
    echo.
)

:: Run the multi-threaded analyzer
echo [>] Running Multi-threaded DPI Engine...
echo [>] Input:  %INPUT_PCAP%
echo [>] Output: %OUTPUT_PCAP%
echo.

python -m src.dpi_mt %INPUT_PCAP% %OUTPUT_PCAP% --fps %WORKERS%

if errorlevel 1 (
    echo.
    echo [!] Analyzer failed to run.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo       Process Complete!
echo ==========================================
pause
