# Shadow Stack Walk

[Gabriel Landau](https://twitter.com/GabrielLandau) @ [Elastic Security](https://www.elastic.co/security-labs/security-research)

See accompanying article [here](https://www.elastic.co/security-labs/finding-truth-in-the-shadows).

The shadow stack provides an interesting detection opportunity.  Adversaries can use tools like [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer/tree/master) and [CallStackSpoofer](https://github.com/WithSecureLabs/CallStackSpoofer) to obfuscate their presence against thread stack scans (e.g. `StackWalk64`) and inline stack traces like [Sysmon operations](https://www.lares.com/blog/hunting-in-the-sysmon-call-trace/).

By comparing a traditional stack walk against its shadowy sibling, we can both detect and see through thread stack spoofing.  This tool implements `CaptureStackBackTrace`/`StackWalk64` with the shadow stack (aka CET/HSP) to catch thread stack spoofing.  When the stack is normal, it functions similarly to `CaptureStackBackTrace` and `StackWalk64`:

```
Control run demonstrating equivalent output...

CONTROL CaptureStackBackTrace: dps 000001CE41EDA800
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!main + 0x5f
1: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__scrt_common_main_seh + 0x10c
2: \Device\HarddiskVolume3\Windows\System32\kernel32.dll!BaseThreadInitThunk + 0x14
3: \Device\HarddiskVolume3\Windows\System32\ntdll.dll!RtlUserThreadStart + 0x21

CONTROL StackWalk64: dps 000001CE42F80D80
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!main + 0x5f
1: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__scrt_common_main_seh + 0x10c
2: \Device\HarddiskVolume3\Windows\System32\kernel32.dll!BaseThreadInitThunk + 0x14
3: \Device\HarddiskVolume3\Windows\System32\ntdll.dll!RtlUserThreadStart + 0x21

CONTROL CET Stack: dps 000001CE41ED79C0
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!main + 0x5f
1: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__scrt_common_main_seh + 0x10c
2: \Device\HarddiskVolume3\Windows\System32\kernel32.dll!BaseThreadInitThunk + 0x14
3: \Device\HarddiskVolume3\Windows\System32\ntdll.dll!RtlUserThreadStart + 0x21
```

It's unaffected by intentional breaks of the call stack such as [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer/blob/f67caea38a7acdb526eae3aac7c451a08edef6a9/ThreadStackSpoofer/main.cpp#L20-L25).

```
Breaking stack walk with a NULL return address...

BROKEN CaptureStackBackTrace: dps 000001CE41ED79C0
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!SpoofStackThenCall + 0x40

BROKEN StackWalk64: dps 000001CE42E1FCD0
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!SpoofStackThenCall + 0x40

BROKEN CET Stack: dps 000001CE41F23020
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!SpoofStackThenCall + 0x40
1: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!main + 0x8c
2: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__scrt_common_main_seh + 0x10c
3: \Device\HarddiskVolume3\Windows\System32\kernel32.dll!BaseThreadInitThunk + 0x14
4: \Device\HarddiskVolume3\Windows\System32\ntdll.dll!RtlUserThreadStart + 0x21
```

It doesn't care about forged stack frames:
```
Spoofing call stack to hide ShadowStackWalk.exe!main...

SPOOFED CaptureStackBackTrace: dps 000001CE41ED79C0
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!SpoofStackThenCall + 0x40
1: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__scrt_common_main_seh + 0x10c
2: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__xi_z + 0x0

SPOOFED StackWalk64: dps 000001CE41F23020
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!SpoofStackThenCall + 0x40
1: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__scrt_common_main_seh + 0x10c
2: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__xi_z + 0x0

SPOOFED CET Stack: dps 000001CE42C927C0
0: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!SpoofStackThenCall + 0x40
1: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!main + 0xbe
2: \Device\HarddiskVolume3\git\ShadowStackWalk\x64\Release\ShadowStackWalk.exe!__scrt_common_main_seh + 0x10c
3: \Device\HarddiskVolume3\Windows\System32\kernel32.dll!BaseThreadInitThunk + 0x14
4: \Device\HarddiskVolume3\Windows\System32\ntdll.dll!RtlUserThreadStart + 0x21
```
