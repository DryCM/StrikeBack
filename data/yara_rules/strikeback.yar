/*
  StrikeBack — Reglas YARA integradas
  ====================================
  Reglas de detección de malware para el YARA Scanner de StrikeBack.
  Cubren las familias más prevalentes: ransomware, RATs, loaders,
  herramientas ofensivas (Cobalt Strike, Metasploit, Mimikatz) y
  técnicas de evasión comunes.

  Clasificación MITRE ATT&CK incluida en los metadatos de cada regla.
  Todas las reglas son de detección estática (análisis de bytes).
*/

// ═══════════════════════════════════════════════════════════
// COBALT STRIKE
// ═══════════════════════════════════════════════════════════

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon — payload de C2 más utilizado en APTs"
        mitre       = "T1059.003"
        severity    = 10
        author      = "StrikeBack"
    strings:
        $cs1 = "%s as %s\\%s" wide ascii
        $cs2 = "beacon.dll" nocase
        $cs4 = "ReflectiveLoader" ascii
        $cs5 = "%%COMSPEC%% /C start" wide ascii
        $cs6 = "IEX (New-Object Net.WebClient)" nocase
    condition:
        2 of them
}

rule CobaltStrike_SleepMask {
    meta:
        description = "Cobalt Strike Sleep Mask — técnica de ofuscación en memoria"
        mitre       = "T1027"
        severity    = 9
        author      = "StrikeBack"
    strings:
        $sm1 = "sleep_mask" ascii
        $sm2 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 }
        $sm3 = "BeaconInject" ascii
    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════
// MIMIKATZ
// ═══════════════════════════════════════════════════════════

rule Mimikatz_Generic {
    meta:
        description = "Mimikatz — herramienta de volcado de credenciales"
        mitre       = "T1003.001"
        severity    = 10
        author      = "StrikeBack"
    strings:
        $mimi1 = "mimikatz" nocase
        $mimi2 = "sekurlsa::" ascii
        $mimi3 = "lsadump::" ascii
        $mimi4 = "kerberos::" ascii
        $mimi5 = "privilege::debug" nocase ascii
        $mimi6 = "Pass-The-Hash" nocase
        $mimi7 = "WDigest" ascii
    condition:
        2 of them
}

// ═══════════════════════════════════════════════════════════
// METASPLOIT / METERPRETER
// ═══════════════════════════════════════════════════════════

rule Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter — shell de control remoto"
        mitre       = "T1059"
        severity    = 10
        author      = "StrikeBack"
    strings:
        $m1 = "meterpreter" nocase
        $m2 = "Meterpreter session" ascii
        $m3 = "ReflectiveDllInjection" ascii
        $m4 = "MSFPAYLOAD" ascii
        $m5 = "msfvenom" nocase
        $m6 = { 6D 65 74 65 72 70 72 65 74 65 72 }
    condition:
        any of them
}

rule Metasploit_Shellcode {
    meta:
        description = "Shellcode de Metasploit — patrón de decodificador"
        mitre       = "T1055"
        severity    = 9
        author      = "StrikeBack"
    strings:
        // Decodificador shikata-ga-nai (patrón característico)
        $shk1 = { D9 74 24 F4 5B 29 C9 B1 }
        $shk2 = { FC E8 8? 00 00 00 60 89 E5 31 D2 }
        $shk3 = { EB 27 5B 53 5E 53 50 FF 37 FF 36 }
    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════
// RANSOMWARE
// ═══════════════════════════════════════════════════════════

rule Ransomware_Generic_Note {
    meta:
        description = "Nota de rescate de ransomware genérica"
        mitre       = "T1486"
        severity    = 10
        author      = "StrikeBack"
    strings:
        $rn1 = "YOUR FILES ARE ENCRYPTED" nocase
        $rn2 = "All your files have been encrypted" nocase
        $rn3 = "To decrypt your files" nocase
        $rn4 = "bitcoin" nocase
        $rn5 = "BTC wallet" nocase
        $rn6 = "decrypt your data" nocase
        $rn7 = "pay the ransom" nocase
        $rn8 = ".onion" nocase
        $rn9 = "HOW TO RECOVER" nocase
    condition:
        3 of them
}

rule Ransomware_WannaCry {
    meta:
        description = "WannaCry / WannaCrypt ransomware"
        mitre       = "T1486"
        severity    = 10
        author      = "StrikeBack"
    strings:
        $wc1 = "WannaCrypt" ascii
        $wc2 = "WANNACRY" nocase
        $wc3 = "wncry" ascii
        $wc4 = "tasksche.exe" nocase
        $wc5 = "@WanaDecryptor@" ascii
        $wc6 = { 57 61 6E 6E 61 43 72 79 }
    condition:
        2 of them
}

rule Ransomware_LockBit {
    meta:
        description = "LockBit ransomware"
        mitre       = "T1486"
        severity    = 10
        author      = "StrikeBack"
    strings:
        $lb1 = "LockBit" nocase
        $lb2 = "Restore-My-Files.txt" nocase
        $lb3 = ".lockbit" ascii
        $lb4 = "LockBit_Ransomware.hta" nocase
    condition:
        any of them
}

rule Ransomware_Ryuk {
    meta:
        description = "Ryuk ransomware"
        mitre       = "T1486"
        severity    = 10
        author      = "StrikeBack"
    strings:
        $r1 = "RyukReadMe" nocase
        $r2 = "UNIQUE_ID_DO_NOT_REMOVE" ascii
        $r3 = "ryuk" nocase
        $r4 = "No system is safe" ascii
    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════
// REMOTE ACCESS TROJANS (RATs)
// ═══════════════════════════════════════════════════════════

rule RAT_AsyncRAT {
    meta:
        description = "AsyncRAT — troyano de acceso remoto"
        mitre       = "T1219"
        severity    = 9
        author      = "StrikeBack"
    strings:
        $a1 = "AsyncRAT" ascii
        $a2 = "Client.Settings" ascii
        $a3 = "Pastebin" ascii
        $a4 = "KeyLogger" nocase
        $a5 = "RecvPacket" ascii
    condition:
        2 of them
}

rule RAT_NjRAT {
    meta:
        description = "NjRAT / Bladabindi — RAT ampliamente distribuido"
        mitre       = "T1219"
        severity    = 9
        author      = "StrikeBack"
    strings:
        $n1 = "njRAT" ascii
        $n2 = "njq8" ascii
        $n3 = "Bladabindi" ascii
        $n4 = "[ServerManager]" ascii
    condition:
        any of them
}

rule RAT_QuasarRAT {
    meta:
        description = "Quasar RAT — RAT de código abierto usado en APTs"
        mitre       = "T1219"
        severity    = 9
        author      = "StrikeBack"
    strings:
        $q1 = "QuasarRAT" ascii
        $q2 = "Quasar.Client" ascii
        $q3 = "Quasar.Common" ascii
        $q4 = "Client.exe" ascii
    condition:
        2 of them
}

// ═══════════════════════════════════════════════════════════
// LOADERS / DROPPERS
// ═══════════════════════════════════════════════════════════

rule Loader_GuLoader {
    meta:
        description = "GuLoader — downloader ofuscado de primera etapa"
        mitre       = "T1105"
        severity    = 8
        author      = "StrikeBack"
    strings:
        $g1 = "GuLoader" ascii nocase
        $g2 = { 60 9C FC 0F 85 }
        $g3 = "VirtualAlloc" ascii
        $g4 = "NtUnmapViewOfSection" ascii
    condition:
        2 of them
}

rule Loader_PrivateLoader {
    meta:
        description = "PrivateLoader — MaaS loader con geo-filtering"
        mitre       = "T1105"
        severity    = 8
        author      = "StrikeBack"
    strings:
        $p1 = "PrivateLoader" nocase
        $p2 = "getFile" ascii
        $p3 = "checkCRC" ascii
    condition:
        2 of them
}

// ═══════════════════════════════════════════════════════════
// HERRAMIENTAS DE POST-EXPLOTACIÓN
// ═══════════════════════════════════════════════════════════

rule PostExploit_BloodHound {
    meta:
        description = "BloodHound — enumeración de Active Directory"
        mitre       = "T1069.002"
        severity    = 8
        author      = "StrikeBack"
    strings:
        $b1 = "BloodHound" ascii nocase
        $b2 = "SharpHound" ascii nocase
        $b3 = "ACL Attack Paths" ascii
        $b4 = "GetDomainGroupMember" ascii
    condition:
        any of them
}

rule PostExploit_Rubeus {
    meta:
        description = "Rubeus — abuso de Kerberos"
        mitre       = "T1558"
        severity    = 9
        author      = "StrikeBack"
    strings:
        $r1 = "Rubeus" ascii
        $r2 = "asktgt" ascii nocase
        $r3 = "kerberoast" ascii nocase
        $r4 = "s4u" ascii nocase
        $r5 = "PassTheTicket" ascii nocase
    condition:
        2 of them
}

rule PostExploit_Impacket {
    meta:
        description = "Impacket — librería Python de protocolos de red usada en ataques"
        mitre       = "T1021.002"
        severity    = 8
        author      = "StrikeBack"
    strings:
        $i1 = "impacket" nocase
        $i2 = "secretsdump" nocase
        $i3 = "psexec.py" nocase
        $i4 = "wmiexec.py" nocase
        $i5 = "smbexec.py" nocase
    condition:
        any of them
}

// ═══════════════════════════════════════════════════════════
// TÉCNICAS DE EVASIÓN
// ═══════════════════════════════════════════════════════════

rule Evasion_AMSI_Bypass {
    meta:
        description = "Bypass de AMSI (Anti-Malware Scan Interface)"
        mitre       = "T1562.001"
        severity    = 8
        author      = "StrikeBack"
    strings:
        $a1 = "amsiInitFailed" nocase
        $a2 = "AmsiScanBuffer" nocase
        $a3 = "amsi.dll" nocase
        $a4 = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')" nocase
        $a5 = "AmsiContext" ascii
    condition:
        any of them
}

rule Evasion_ETW_Bypass {
    meta:
        description = "Bypass de ETW (Event Tracing for Windows)"
        mitre       = "T1562.006"
        severity    = 8
        author      = "StrikeBack"
    strings:
        $e1 = "EtwEventWrite" ascii
        $e2 = { C3 90 90 90 90 }  // RET + NOPs (parche de función)
        $e3 = "ntdll.dll" ascii
        $e4 = "EtwpCreateEtwThread" ascii
    condition:
        2 of ($e1, $e3, $e4) or $e2
}

rule Evasion_Powershell_Encoded {
    meta:
        description = "PowerShell con comandos codificados en Base64 — evasión común"
        mitre       = "T1027"
        severity    = 7
        author      = "StrikeBack"
    strings:
        $p1 = "-EncodedCommand" nocase
        $p2 = "-enc " nocase
        $p3 = "-nop " nocase
        $p4 = "-w hidden" nocase
        $p5 = "-WindowStyle Hidden" nocase
        $p6 = "FromBase64String" nocase
        $p7 = "IEX" ascii
        $p8 = "Invoke-Expression" nocase
    condition:
        3 of them
}

// ═══════════════════════════════════════════════════════════
// KEYLOGGERS / SPYWARE
// ═══════════════════════════════════════════════════════════

rule Spyware_Keylogger {
    meta:
        description = "Keylogger — captura de pulsaciones de teclado"
        mitre       = "T1056.001"
        severity    = 8
        author      = "StrikeBack"
    strings:
        $k1 = "SetWindowsHookEx" ascii
        $k2 = "GetAsyncKeyState" ascii
        $k3 = "WH_KEYBOARD_LL" ascii
        $k4 = "keylogger" nocase
        $k5 = "KeyLogger" ascii
    condition:
        2 of them
}

// ═══════════════════════════════════════════════════════════
// CRYPTOMINERS
// ═══════════════════════════════════════════════════════════

rule Cryptominer_XMRig {
    meta:
        description = "XMRig — miner de Monero usado en cryptojacking"
        mitre       = "T1496"
        severity    = 7
        author      = "StrikeBack"
    strings:
        $x1 = "xmrig" nocase
        $x2 = "stratum+tcp" ascii
        $x3 = "monero" nocase
        $x4 = "cryptonight" nocase
        $x5 = "--donate-level" ascii
        $x6 = "nicehash" nocase
    condition:
        2 of them
}
