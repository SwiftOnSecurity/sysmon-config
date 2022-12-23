@echo off
SETLOCAL ENABLEEXTENSIONS
SET MYDIR= %~dp0
SET CMD_SWITCH=%1
cls

REM Reset any Errorlevel to zero
ver >NUL

REM Check for Administrative permissions
net session >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
	echo Administrative permissions required.
	goto EOF
)

IF DEFINED CMD_SWITCH (
	IF "%CMD_SWITCH%"=="u" (
		echo Removing SYSMON...
		%MYDIR%sysmon64 -u force >NUL 2>&1
		goto EOF
	)
	echo To uninstall SYSMON use this script with parameter u.
	goto EOF
)

REM Reset any Errorlevel to zero
ver >NUL

REM Check if Sysmon64 is already installed
sc query sysmon64 | find /I "TYPE" >NUL

IF %ERRORLEVEL% NEQ 0 (
	REM SYSMON is not installed -> New system
	echo Installing Sysmon
	%MYDIR%sysmon64 -i %MYDIR%sysmonconfig-export.xml -accepteula >NUL 2>&1
) ELSE (
	REM SYSMON is installed -> Config will be updated
	echo Updating Config
	%MYDIR%sysmon64 -c %MYDIR%sysmonconfig-export.xml >NUL 2>&1
)

ENDLOCAL

:EOF

