#include <windows.h>
#include <stdio.h>
#include <lm.h>

// Define the structure of the call
typedef BOOL (WINAPI* myNotGetComputerNameA)(
   LPSTR lpBuffer,
   LPDWORD nSize
);

int main() {
    // Obtain the handle of the module the call address is present in
    HMODULE hkernel32 = LoadLibraryA(“kernel32.dll”);
    
    // Obtain the process address of the call
    myNotGetComputerNameA notGetComputerNameA = (myNotGetComputerNameA) GetProcAddress(hkernel32, “GetComputerNameA”);
}
