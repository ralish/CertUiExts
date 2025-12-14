@ECHO OFF

WHERE /Q "MSBuild.exe"
IF %ERRORLEVEL% GEQ 1 (
    ECHO [CertUiExts] Unable to build as MSBuild was not found.
    EXIT /B 1
)

@REM Switch to repository root directory
PUSHD "%~dp0\.."

@REM Default MSBuild arguments
SET MSBuildSln=CertUiExts.slnx
SET MSBuildArgs=-noLogo -verbosity:minimal -maxCpuCount
SET MSBuildTarget=Build

@REM Optional first arg is build target
IF NOT "%1" == "" SET MSBuildTarget=%1

ECHO [CertUiExts] Running target "%MSBuildTarget%" for Debug/x86 ...
MSBuild %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Debug;Platform=x86
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [CertUiExts] Running target "%MSBuildTarget%" for Debug/x64 ...
MSBuild %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Debug;Platform=x64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [CertUiExts] Running target "%MSBuildTarget%" for Debug/ARM64 ...
MSBuild %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Debug;Platform=ARM64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [CertUiExts] Running target "%MSBuildTarget%" for Release/x86 ...
MSBuild %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Release;Platform=x86
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [CertUiExts] Running target "%MSBuildTarget%" for Release/x64 ...
MSBuild %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Release;Platform=x64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [CertUiExts] Running target "%MSBuildTarget%" for Release/ARM64 ...
MSBuild %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Release;Platform=ARM64
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

:End
@REM Clean-up script variables
SET MSBuildSln=
SET MSBuildArgs=
SET MSBuildTarget=

@REM Restore original directory
POPD
