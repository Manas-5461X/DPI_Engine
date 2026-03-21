@echo off
setlocal

:: ==========================================
::       Advanced Blocking Settings
:: ==========================================
:: Change these values to block specific traffic:

set INPUT_PCAP=test_dpi.pcap
set OUTPUT_PCAP=output_advanced.pcap
set WORKERS=4

:: 1. Block an Application (e.g., YouTube, Facebook, TikTok)
:: Leave empty if you don't want to block any app.
set BLOCK_APP=YouTube

:: 2. Block a specific IP Address
:: Leave empty if you don't want to block any IP.
set BLOCK_IP=192.168.1.50

:: 3. Block a Domain (substring match, e.g., google, tiktok)
:: Leave empty if you don't want to block any domain.
set BLOCK_DOMAIN=

:: ==========================================

echo ==========================================
echo       Packet Analyzer ADVANCED Run
echo ==========================================
echo.

:: Build the command with flags if they are set
set FLAGS=--fps %WORKERS%
if not "%BLOCK_APP%"=="" set FLAGS=%FLAGS% --block-app %BLOCK_APP%
if not "%BLOCK_IP%"=="" set FLAGS=%FLAGS% --block-ip %BLOCK_IP%
if not "%BLOCK_DOMAIN%"=="" set FLAGS=%FLAGS% --block-domain %BLOCK_DOMAIN%

:: Check for input file, generate if missing
if not exist %INPUT_PCAP% (
    echo [!] %INPUT_PCAP% not found. Generating test data...
    python generate_test_pcap.py
)

:: Run the multi-threaded analyzer
echo [>] Running Multi-threaded DPI Engine...
echo [>] Input:  %INPUT_PCAP%
echo [>] Output: %OUTPUT_PCAP%
if not "%BLOCK_APP%"=="" echo [>] Blocking App: %BLOCK_APP%
if not "%BLOCK_IP%"=="" echo [>] Blocking IP:  %BLOCK_IP%
if not "%BLOCK_DOMAIN%"=="" echo [>] Blocking Domain: %BLOCK_DOMAIN%
echo.

python -m src.dpi_mt %INPUT_PCAP% %OUTPUT_PCAP% %FLAGS%

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
