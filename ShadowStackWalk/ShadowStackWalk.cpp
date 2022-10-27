// ShadowStackWalk.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <intrin.h>
#include <DbgHelp.h>
#include <Psapi.h>

#pragma optimize("", off)

void SymInit(HANDLE hProcess)
{
    std::wstring myPath(USHRT_MAX, L'\0');
    std::wstring myDir;
    myPath.resize(GetModuleFileNameW(NULL, &myPath[0], (DWORD)myPath.size()));
    myDir = myPath.substr(0, myPath.rfind('\\'));

    if (!SymInitializeW(hProcess, myDir.c_str(), TRUE))
    {
        printf("SymInitializeW failed with GLE %u\n", GetLastError());
    }
}

PVOID WINAPI GetSSP(HANDLE hThread)
{
    PCONTEXT pCtx = NULL;
    DWORD64 featureMask = 0;
    DWORD contextLength = 0;
    std::string buf;
    PXSAVE_CET_U_FORMAT pCet = NULL;
    DWORD cetLength = 0;

    if (!(GetEnabledXStateFeatures() & XSTATE_MASK_CET_U))
    {
        printf("XSTATE_MASK_CET_U is not enabled!\n");
        return 0;
    }

    (void)InitializeContext2(NULL, CONTEXT_XSTATE, NULL, &contextLength, XSTATE_MASK_CET_U);
    if (0 == contextLength)
    {
        printf("InitializeContext2 call 1 failed with GLE %u\n", GetLastError());
        return NULL;
    }

    buf.resize(contextLength);
    if (!InitializeContext2(&buf[0], CONTEXT_XSTATE, &pCtx, &contextLength, XSTATE_MASK_CET_U))
    {
        printf("InitializeContext2 call 2 failed with GLE %u\n", GetLastError());
        return NULL;
    }

    if (!GetThreadContext(hThread, pCtx))
    {
        printf("GetThreadContext failed with GLE %u\n", GetLastError());
        return NULL;
    }

    if (!GetXStateFeaturesMask(pCtx, &featureMask))
    {
        printf("GetXStateFeaturesMask failed with GLE %u\n", GetLastError());
        return NULL;
    }

    if (!(XSTATE_MASK_CET_U & featureMask))
    {
        printf("CET is not enabled on this thread\n");
        return NULL;
    }

    pCet = (PXSAVE_CET_U_FORMAT)LocateXStateFeature(pCtx, XSTATE_CET_U, &cetLength);
    if (!pCet || (sizeof(*pCet) != cetLength))
    {
        printf("Failed to locate XSTATE_MASK_CET_U feature\n");
        return NULL;
    }

    return (PVOID)pCet->Ia32Pl3SspMsr;
}

USHORT WINAPI CaptureStackBackTrace_CET(
    _In_      ULONG  FramesToSkip,
    _In_      ULONG  FramesToCapture,
    _Out_     PVOID* BackTrace
)
{
    USHORT frameCount = 0;

    PVOID* pSSP = (PVOID*)GetSSP(GetCurrentThread());
    
    if (!pSSP)
    {
        printf("CET not supported\n");
        return 0;
    }

    // Based on:
    // https://github.com/yardenshafir/cet-research/blob/f97cfb131165cb524671dc9ff0dbd8dcedfbf2d1/src/KiVerifyContextIpForUserCet.c#L145-L153
    __try
    {
        for (size_t i = 0; i < FramesToCapture + FramesToSkip; i++)
        {
            if (!((ULONG_PTR)pSSP & 0xFFF)) // Don't cross page boundaries
            {
                break;
            }

            if (i >= FramesToSkip)
            {
                BackTrace[frameCount] = *pSSP;
                frameCount++;
            }
            
            pSSP++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return frameCount;
}

USHORT WINAPI CaptureStackBackTrace_StackWalk64(
    _In_      ULONG  FramesToSkip,
    _In_      ULONG  FramesToCapture,
    _Out_     PVOID* BackTrace
)
{
    USHORT frameCount = 0;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();
    STACKFRAME64 stackFrame = { 0 };
    CONTEXT ctx = { 0, };

    SymInit(GetCurrentProcess());

    ctx.ContextFlags = CONTEXT_CONTROL;
    RtlCaptureContext(&ctx);

    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrPC.Offset = ctx.Rip;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = ctx.Rsp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = ctx.Rbp;

    for (size_t i = 0; i < FramesToCapture + FramesToSkip; i++)
    {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &stackFrame, &ctx, NULL, 0, 0, NULL))
        {
            break;
        }

        if (i >= FramesToSkip)
        {
            BackTrace[frameCount] = (PVOID)stackFrame.AddrPC.Offset;
            frameCount++;
        }
    }

    SymCleanup(GetCurrentProcess());

    return frameCount;
}

#define MAX_SYMBOL_LENGTH 32768
void PrintStackFrame(HANDLE hProcess, ULONG number, PVOID address)
{
    PSYMBOL_INFOW pSymInfo = (PSYMBOL_INFOW)alloca(sizeof(SYMBOL_INFOW) + MAX_SYMBOL_LENGTH);
    DWORD64 displacement = 0;
    MEMORY_BASIC_INFORMATION mbi = { 0, };
    std::wstring module;

    ZeroMemory(pSymInfo, sizeof(SYMBOL_INFOW) + MAX_SYMBOL_LENGTH);
    pSymInfo->SizeOfStruct = sizeof(*pSymInfo);
    pSymInfo->MaxNameLen = MAX_SYMBOL_LENGTH;

    VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi));
    switch (mbi.Type)
    {
    case MEM_PRIVATE:
        module = L"UNBACKED";
        break;
    case MEM_MAPPED:
        module = L"MAPPED";
        break;
    case MEM_IMAGE:
        module.resize(USHRT_MAX);
        module.resize(GetMappedFileNameW(hProcess, address, &module[0], (DWORD)module.size()));
        if (module.empty())
        {
            module = L"UNKNOWNIMAGE";
        }
        break;
    default:
        module = L"UNKNOWN";
    }

    if (SymFromAddrW(hProcess, (DWORD64)address, &displacement, pSymInfo))
    {
        wprintf(L"%u: %ws!%ws + 0x%llx\n", number, module.c_str(), pSymInfo->Name, displacement);
    }
    else
    {
        wprintf(L"%u: %ws (%p)\n", number, module.c_str(), address);
    }
}

void PrintStackTrace(HANDLE hProcess, const std::vector<PVOID>& stack)
{
    SymInit(hProcess);

    for (ULONG i = 0; i < stack.size(); i++)
    {
        PrintStackFrame(hProcess, i, stack[i]);
    }

    SymCleanup(hProcess);
}

void Demo_CaptureStackBackTrace(const char * testName)
{
    std::vector<PVOID> csbt;
    std::vector<PVOID> cetFrames;
    std::vector<PVOID> sw64Frames;

    csbt.resize(64);
    csbt.resize(CaptureStackBackTrace(1, (DWORD)csbt.size(), &csbt[0], NULL));
    if (!csbt.empty())
    {
        printf("\n%s CaptureStackBackTrace: dps %p\n", testName, &csbt[0]);
        PrintStackTrace(GetCurrentProcess(), csbt);
    }

    sw64Frames.resize(64);
    sw64Frames.resize(CaptureStackBackTrace_StackWalk64(2, (DWORD)sw64Frames.size(), &sw64Frames[0]));
    if (!sw64Frames.empty())
    {
        printf("\n%s StackWalk64: dps %p\n", testName, &sw64Frames[0]);
        PrintStackTrace(GetCurrentProcess(), sw64Frames);
    }

    cetFrames.resize(64);
    cetFrames.resize(CaptureStackBackTrace_CET(4, (DWORD)cetFrames.size(), &cetFrames[0]));
    if (!cetFrames.empty())
    {
        printf("\n%s CET Stack: dps %p\n", testName, &cetFrames[0]);
        PrintStackTrace(GetCurrentProcess(), cetFrames);
    }


}

typedef void (callme_t)(const char* testName);

void SpoofStackThenCall(const char* testName, PVOID fakeCaller, callme_t callme)
{
    PVOID* pReturnAddress = (PVOID*)_AddressOfReturnAddress();
    PVOID savedReturnAddress = *pReturnAddress;

    *pReturnAddress = fakeCaller;

    callme(testName);

    *pReturnAddress = savedReturnAddress;
}

// Set *pReturnAddress to NULL to break stack walk
// Emulates https://github.com/mgeeky/ThreadStackSpoofer/blob/f67caea38a7acdb526eae3aac7c451a08edef6a9/ThreadStackSpoofer/main.cpp#L20-L25
#define BreakStackThenCall(_t, _callme) SpoofStackThenCall(_t, NULL, _callme)

int main(int argc, char* argv[])
{
    alloca(1);

    printf("ShadowStackWalk by Gabriel Landau @ Elastic Security\n");
    printf("Demonstrates the shadow stack's ability to detect and circumvent various forms of stack tampering.\n\n");


    printf("Control run demonstrating equivalent output...\n");

    Demo_CaptureStackBackTrace("CONTROL");

    printf("\n==========================================\n\n");

    printf("Breaking stack walk with a NULL return address...\n");

    // Break stack walking
    BreakStackThenCall("BROKEN", Demo_CaptureStackBackTrace);

    printf("\n==========================================\n\n");

    printf("Spoofing call stack to hide ShadowStackWalk.exe!main...\n");

    // Skip over main() in the callstack
    SpoofStackThenCall("SPOOFED", _ReturnAddress(), Demo_CaptureStackBackTrace);

    return 0;
}
