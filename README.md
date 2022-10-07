
<h3 align="center">Win-Rev-Shell</h3>

<div align="center">
<p align="center">
A fully undetected assembly reverse shell backdoor for Windows.
</p>
<br />

<br />

<a href="https://github.com/Ay0ubN0uri/win-rev-shell/issues">Report Issue</a>
<span>|</span>
<a href="https://github.com/Ay0ubN0uri/win-rev-shell/issues">Request Feature</a>
</div>

## Prerequisites:


### Nasm:

- Nasm should be preinstalled on latest versions of Windows.

- You can check by running `nasm --version` on command prompt.

- If nasm is not installed, [click here](https://www.nasm.us/).

<br />

## Installation / How to use:

- Very simple, Change the ip and the port in the asm file.

- Use the `compile.bat` file to compile and link the asm file. Example : `compile.bat backdoor`.

- Run a netcat listener on attacker machine to get a shell back. Example: `nc -lvvp 3322`.

- If you want to use a shellcode use the `shellcode.c` file.

<br />

## Undetected: 
- Use the `xor encoder version`.
- Follow the same steps above for the asm file.
- [Virus Scan Results](https://antiscan.me/scan/new/result?id=luloyNAQYlMz).


## Contact

- LinkedIn: [ayoub nouri](https://www.linkedin.com/in/ayoub-nouri-73532a244/)

- Email: ayoub.nouri105@gmail.com

- Project Link: [https://github.com/Ay0ubN0uri/win-rev-shell](https://github.com/Ay0ubN0uri/win-rev-shell)
