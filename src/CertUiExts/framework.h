#pragma once

// Exclude infrequently used Windows headers
#define WIN32_LEAN_AND_MEAN

// Source-code Annotation Language (SAL)
#include <sal.h>

// CRT headers
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>

// Windows headers
#include <windows.h>
#include <sddl.h>
#include <wincrypt.h>
#include <wintrust.h>

// Common headers
#include "Shared.h"
#include "CertUiExts.h"
