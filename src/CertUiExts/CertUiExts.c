#include "pch.h"

BOOL WINAPI DllMain(_In_ const HINSTANCE hinstDLL,
                    _In_ const DWORD fdwReason,
                    _In_ const LPVOID lpvReserved) {
    UNREFERENCED_PARAMETER(lpvReserved);

    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Disable DLL_THREAD_ATTACH and DLL_THREAD_DETACH notifications
        DisableThreadLibraryCalls(hinstDLL);
    }

    return TRUE;
}
