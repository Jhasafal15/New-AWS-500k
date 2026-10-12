@echo off
title Cloud Sentinel AI - Security Posture Analyzer
cd /d "%~dp0"

echo ================================================================================
echo       AI-POWERED CLOUD SECURITY POSTURE MANAGEMENT (CSPM)
echo                UNIVERSAL DATASET ANALYSIS RUNNER
echo ================================================================================
echo.

if "%~1"=="" (
    echo No input file provided.
    echo Running analysis on baseline / latest dataset...
    echo.
    python run_analysis.py
) else (
    echo Target Dataset: %~1
    echo.
    python run_analysis.py --input "%~1"
)

if exist dashboard.html (
    echo.
    echo [INFO] Opening interactive Cyber SOC Dashboard in browser...
    start dashboard.html
)

echo.
echo ================================================================================
echo Analysis complete. You can close this window at any time.
echo ================================================================================
pause
