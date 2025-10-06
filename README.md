# Challenge: sanity checksanity

Category: social / sanity
Author: jailctf org team

Summary:
The flag is embedded in the server rules. The visible message is obfuscated with repeated characters. The rules instruct you to right-click the first message and use Copy Text. That action reveals the hidden flag text.

Key insight:
Discord’s Copy Text copies the raw message contents. Obfuscation intended for humans is preserved when copying. The flag is present in the copied text even if the message looks noisy.

Steps to solve:
Join the Discord server -> Open the rules channel -> Right-click the first message -> Choose Copy Text -> Paste into a text editor -> Scan the pasted content for the flag pattern jail{...}

Flag:
```
jail{welcome_to_jailctf_2025!!!}
```

<img width="1466" height="350" alt="image" src="https://github.com/user-attachments/assets/c9939ebe-9a29-4657-8ef8-16b5e62dca3a" />


<img width="1132" height="528" alt="image" src="https://github.com/user-attachments/assets/d9d5ff1d-dad3-4516-b297-0c795e474a05" />

______

# Challenge: blindness (pyjail)

Category: pyjail
Author: @helloperson

Problem summary:
__builtins__ is emptied. No print, no open, no helpers.
sys.stdout is closed. Normal output is invisible.
flag is present in the eval scope

Key insight:
Tracebacks and error messages are written to stderr, which is still open. If we cause an exception whose message contains the flag value, the flag will be printed to stderr and thus visible to the attacker.
Exploit:
We need an expression that evaluates flag then causes an exception that includes the evaluated value in its error message. A dictionary lookup fits:

Payload:
{}[flag]
Why this works:

Python evaluates flag to the flag string.
{} is an empty dict. Attempting {}[flag] looks up the flag string as a key.
That raises KeyError: '<flag_string>'. The KeyError message contains the key value quoted.
The traceback is emitted to stderr, so we see the flag even though stdout is closed and builtins are disabled.
Example result (illustrative):
```Traceback (most recent call last):
  File "<string>", line 1, in <module>
KeyError: 'jail{stderr_leak_5fd787f079eb69e}'
```
Alternatives considered:
Causing other exceptions that display values. Many type/index errors do not include the offending value.
Complex attribute/class introspection can work but is unnecessary here. The empty-dict lookup is the simplest and most reliable.
Flag:
`jail{stderr_leak_5fd787f079eb69e}`
<img width="1786" height="328" alt="image" src="https://github.com/user-attachments/assets/e3d3b92b-6d89-4d0e-8592-e4ead8f4ce5b" />
____________
# Challenge: ASMaaSassembly (pyasm)

Category: pwn / asm
Author: @lydxn

Problem:
The service does not execute shellcode. It only assembles input and prints the resulting bytes as hex. The goal is to exfiltrate flag.txt.

Key insight:
The GNU assembler supports .incbin to embed raw file bytes into the assembled output. The assembler runs in the jail where flag.txt is reachable. The service prints assembled bytes as hex. Embedding the flag directly in the output leaks it.

Exploit:
Send this as input:
`.incbin "flag.txt"`

Server response (hex snippet):
```Compiled shellcode to X86!
6a 61 69 6c 7b 79 65 61 68 5f 6a 75 73 74 5f 69 6e 63 6c 75 64 65 5f 66 6c 61 67 2e 74 78 74 5f 6c 6f 6c 7d 0a
```
Convert the hex to raw bytes then to ASCII:
python3 -c "print(bytes.fromhex('6a 61 69 6c 7b 79 65 61 68 5f 6a 75 73 74 5f 69 6e 63 6c 75 64 65 5f 66 6c 61 67 2e 74 78 74 5f 6c 6f 6c 7d 0a').decode())"
Flag:
`jail{yeah_just_include_flag.txt_lol}`

<img width="2176" height="174" alt="image" src="https://github.com/user-attachments/assets/10ec3891-fc54-4bfe-bdc1-c98c0c35c94d" />
____________
# computer-monitor (pyjail) — short write-up

## Challenge summary

You’re dropped into a Python REPL-like jail. Whatever you type is `compile`d and then executed **with a sys.monitoring hook that kills the process on any CALL or BRANCH**. Concretely, the jail:

* compiles your input to a code object `code`
* enables monitoring only for `BRANCH` and `CALL` events **on that code object**
* registers a callback `exit_hook = lambda *a: _exit(0)` for both events
* executes your code with `exec(code, {}, {})` 

A local `flag.txt` exists (on remote it holds the real flag). 

## Root cause

Inside `exit_hook`, the name `_exit` is a **global lookup** performed at function runtime. Since monitoring is set **only** for `BRANCH` and `CALL` on your `code` object, you can do operations that are neither a call nor a branch (e.g., attribute/subscript assignments) to **rebind the global `_exit`** in the `__main__` module **before** triggering any monitored event. When the first monitored event fires, the callback tries to run `_exit(0)`—but now `_exit` points to something harmless.
Key details from the jail code: `sm.set_local_events(2, code, sm.events.BRANCH + sm.events.CALL)` and `exit_hook = lambda *a: _exit(0)` followed by `sm.register_callback(..., exit_hook)`. 

## Exploit payload
Minimal one-liner:
```py
import sys; sys.modules['__main__'].__dict__['_exit']=int; print(open('flag.txt').read())
```

Why it works:

* `import sys` + dictionary assignment don’t produce Python **CALL**/**BRANCH** in your code object, so no hook yet.
* You rebind `_exit` in `__main__` to `int` (any callable is fine).
* The first actual call (`open` or `print`) triggers the monitor; it invokes `exit_hook`, which now calls your harmless `_exit` instead of `os._exit`, and execution continues, letting you read the flag. 

## Takeaways

* Python’s `sys.monitoring` hooks here only watch **CALL/BRANCH** on the specific user code object; mutating module globals via attribute/subscript ops slips past.
* Functions resolve globals at **call time**; rebinding those names is a classic way to defang preinstalled callbacks in pyjails that don’t block attribute access. 

running the payload shows this
```┌──(kali㉿PC)-[~]
└─$ nc challs2.pyjail.club 28684
> import sys; sys.modules['__main__'].__dict__['_exit']=int; print(open('flag.txt').read())
jail{i_am_proto_your_security_is_my_motto_install_me_on_your_computer_to_protect_your_data_better_f6b37a6e6d0b0af2b5da77a61cd0af7c}
```
