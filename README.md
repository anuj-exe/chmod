# chmod
A simple PowerShell wrapper that brings Linux-style chmod to Windows.
It translates octal (755) and symbolic (u+rw,g-x) modes into NTFS ACL changes using PowerShell and icacls.

- Install
- Clone or download this repo.
- Add the folder to your system PATH.
- Use chmod from cmd or PowerShell.

Usage Examples:
- chmod u+rw,g-w file.txt     # add rw to user, remove w from group
- chmod a=rX -R myfolder      # read + traverse for everyone, recursive
- chmod u=rwx,go= secure.dat  # only owner can read/write/execute

Octal modes
- chmod 644 file.txt      # u=rw, g=r, o=r
- chmod 755 script.ps1    # u=rwx, g=rx, o=rx
- chmod 444 wasm.html     # read-only for all
