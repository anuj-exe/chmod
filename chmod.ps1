param(
  [Parameter(Mandatory=$true, Position=0)]
  [string]$Mode,                                # e.g., 755 or u+rwx,g-w,o=
  [Parameter(Mandatory=$true, Position=1, ValueFromRemainingArguments=$true)]
  [string[]]$Paths,
  [switch]$R                                    
)

# ---- Helpers ---------------------------------------------------------------

function Get-IdentitiesForUGO {
  param($acl)

  # Resolve owner (u)
  $owner = try {
    (New-Object System.Security.Principal.SecurityIdentifier($acl.Owner)).Translate([System.Security.Principal.NTAccount]).Value
  } catch {
    $acl.Owner
  }

  @{
    u = $owner
    g = 'BUILTIN\Users'
    o = 'Everyone'
  }
}

function Get-Rights-FromLetters {
  param(
    [string]$letters,        # e.g., "rwX"
    [bool]$isDir
  )
  $rights = [System.Security.AccessControl.FileSystemRights]0

  if ($letters -match 'r') {
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::ReadData
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::ReadAttributes
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::ReadPermissions
    if ($isDir) {

      $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::ListDirectory
    }
  }
  if ($letters -match 'w') {
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::WriteData
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::AppendData
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes
    $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
  }
  # 'x' (execute/traverse)
  $needsX = $false
  if ($letters -match 'x') { $needsX = $true }
  elseif ($letters -match 'X') { if ($isDir) { $needsX = $true } }  # POSIX-ish 'X' (dir-only)
  if ($needsX) {
    if ($isDir) {
      $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::Traverse
    } else {
      $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::ExecuteFile
    }
  }

  return $rights
}

function Rights-ToLetters {
  # Only for verbose/debug; not used in core application
  param([System.Security.AccessControl.FileSystemRights]$r, [bool]$isDir)
  $s = ""
  if (($r -band [System.Security.AccessControl.FileSystemRights]::ReadData) -ne 0) { $s += "r" }
  if (($r -band [System.Security.AccessControl.FileSystemRights]::WriteData) -ne 0) { $s += "w" }
  if ($isDir) {
    if (($r -band [System.Security.AccessControl.FileSystemRights]::Traverse) -ne 0) { $s += "x" }
  } else {
    if (($r -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) -ne 0) { $s += "x" }
  }
  return $s
}

function Combine-ExplicitRights {
  param($acl, [string]$identity)
  $acc = [System.Security.AccessControl.FileSystemRights]0
  foreach ($ace in $acl.Access) {
    if (-not $ace.IsInherited -and $ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -eq $identity) {
      $acc = $acc -bor $ace.FileSystemRights
    }
  }
  return $acc
}

function Remove-ExplicitForIdentities {
  param($acl, [string[]]$idents)
  foreach ($ace in @($acl.Access)) {
    if (-not $ace.IsInherited -and $ace.AccessControlType -eq 'Allow' -and $idents -contains $ace.IdentityReference.Value) {
      [void]$acl.RemoveAccessRule($ace)
    }
  }
}

function Set-ExplicitAllow {
  param($acl, [string]$identity, [System.Security.AccessControl.FileSystemRights]$rights, [bool]$isDir)
  if ($rights -eq 0) { return }

  $inherit = $isDir ? ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) : [System.Security.AccessControl.InheritanceFlags]::None
  $prop    = [System.Security.AccessControl.PropagationFlags]::None
  $rule    = [System.Security.AccessControl.FileSystemAccessRule]::new($identity, $rights, $inherit, $prop, 'Allow')
  [void]$acl.AddAccessRule($rule)
}

function OctalDigit-ToLetters {
  param([int]$d)
  $s = ""
  if ($d -band 4) { $s += "r" }
  if ($d -band 2) { $s += "w" }
  if ($d -band 1) { $s += "x" }
  return $s
}

function Apply-ModeTo-Item {
  param([string]$mode, [string]$path)

  $item = Get-Item -LiteralPath $path -ErrorAction Stop
  $isDir = $item.PSIsContainer
  $acl = Get-Acl -LiteralPath $path
  $map = Get-IdentitiesForUGO $acl

  # We'll accumulate intended explicit rights per identity,
  # starting from current explicit rights (for + / - semantics).
  $targetIdents = @($map.u, $map.g, $map.o)
  $current = @{
    $map.u = Combine-ExplicitRights $acl $map.u
    $map.g = Combine-ExplicitRights $acl $map.g
    $map.o = Combine-ExplicitRights $acl $map.o
  }

  # Distinguish octal vs symbolic
  if ($mode -match '^[0-7]{3,4}$') {
    if ($mode.Length -eq 4) { $mode = $mode.Substring(1) }  # ignore suid/sgid/sticky
    $u = [int]$mode[0].ToString()
    $g = [int]$mode[1].ToString()
    $o = [int]$mode[2].ToString()

    $lettersU = OctalDigit-ToLetters $u
    $lettersG = OctalDigit-ToLetters $g
    $lettersO = OctalDigit-ToLetters $o

    $rightsU = Get-Rights-FromLetters $lettersU $isDir
    $rightsG = Get-Rights-FromLetters $lettersG $isDir
    $rightsO = Get-Rights-FromLetters $lettersO $isDir

    # '=' semantics: replace explicit rules for u/g/o
    Remove-ExplicitForIdentities $acl $targetIdents
    Set-ExplicitAllow $acl $map.u $rightsU $isDir
    Set-ExplicitAllow $acl $map.g $rightsG $isDir
    Set-ExplicitAllow $acl $map.o $rightsO $isDir
    Set-Acl -LiteralPath $path -AclObject $acl
    return
  }

  # Symbolic: split by commas into clauses like "u+rw", "g-x", "a=rX"
  $clauses = $mode.Split(',') | Where-Object { $_ -ne '' }
  foreach ($cl in $clauses) {
    if ($cl -notmatch '^(?<who>[ugoa]*)(?<op>[+\-=])(?<perms>[rwxX]*)$') {
      throw "Bad symbolic mode clause: '$cl'"
    }
    $who = $Matches['who']; $op = $Matches['op']; $perms = $Matches['perms']
    if ([string]::IsNullOrEmpty($who)) { $who = 'ugo' } 
    if ($who -match 'a') { $who = ($who -replace 'a','') + 'ugo' }

    $permRights = Get-Rights-FromLetters $perms $isDir

    foreach ($ch in ($who.ToCharArray() | Select-Object -Unique)) {
      $id = switch ($ch) { 'u' { $map.u } 'g' { $map.g } 'o' { $map.o } default { continue } }
      $curr = $current[$id]

      switch ($op) {
        '+' { $new = $curr -bor $permRights }
        '-' { $new = $curr -band (-bnot $permRights) }
        '=' { $new = $permRights }
      }

      $current[$id] = $new
    }
  }

  # Rewrite explicit rules for u/g/o with the final combined rights
  Remove-ExplicitForIdentities $acl $targetIdents
  Set-ExplicitAllow $acl $map.u $current[$map.u] $isDir
  Set-ExplicitAllow $acl $map.g $current[$map.g] $isDir
  Set-ExplicitAllow $acl $map.o $current[$map.o] $isDir

  Set-Acl -LiteralPath $path -AclObject $acl
}


$allPaths = @()
foreach ($p in $Paths) {
  if (-not (Test-Path -LiteralPath $p)) {
    Write-Error "No such file or directory: $p"
    continue
  }

  if ($R) {
    $allPaths += (Get-Item -LiteralPath $p)
    $allPaths += Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
  } else {
    $allPaths += (Get-Item -LiteralPath $p)
  }
}

foreach ($it in $allPaths) {
  try {
    Apply-ModeTo-Item -mode $Mode -path $it.FullName
  } catch {
    Write-Error "Failed on '$($it.FullName)': $($_.Exception.Message)"
  }
}
