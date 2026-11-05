@echo off
rem One-click runner for the AWS S3 & IAM security checker.
rem Opens a dialog for AWS profile, region and sign-in, then runs the scan
rem and opens the report. All logic lives in launcher.ps1 next to this file.
title AWS S3 ^& IAM Security Checker
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0launcher.ps1"
rem Keep the window open on errors so the console output can be read.
if errorlevel 1 pause
