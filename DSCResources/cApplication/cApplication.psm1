Enum Ensure{
    Absent
    Present
}

function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet("Present", "Absent")]
        [string]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $InstallerPath,

        [string]
        $ProductId,

        [string]
        $InstalledCheckFilePath,

        [bool]
        $Fuzzy = $false
    )

    # Get Application info
    # $InstalledCheckFilePath has highest priority
    if ($InstalledCheckFilePath) {
        Write-Verbose ('InstalledCheckFilePath is specified. Whether an application exists or not is judged by whether or not the path exists.')
        if (Test-Path $InstalledCheckFilePath) {
            Write-Verbose ('"{0}" is exist.' -f $InstalledCheckFilePath)
            $Program = @{
                DisplayName = $Name
            }
        }
        else {
            Write-Verbose ('"{0}" is not exist.' -f $InstalledCheckFilePath)
            $Program = $null
        }
    }
    # $ProductId take priority over $Name
    elseif ($ProductId) {
        $Program = Get-InstalledProgram -ProductId $ProductId
    }
    else {
        $Program = Get-InstalledProgram -Name $Name -Fuzzy:$Fuzzy
    }

    if (-not $Program) {
        Write-Verbose ('The application "{0}" is not installed.' -f $Name)
        $returnValue = @{
            Ensure        = [Ensure]::Absent
            Name          = ''
            InstallerPath = $InstallerPath
            Installed     = $false
        }
        return $returnValue
    }
    else {
        Write-Verbose ('The application "{0}" is installed.' -f $Program.DisplayName)
        $ProgramInfo = @{
            Ensure          = 'Present'
            Name            = $Program.DisplayName
            ProductId       = $Program.PSChildName
            Version         = $Program.DisplayVersion
            Publisher       = $Program.Publisher
            InstallerPath   = $InstallerPath
            UninstallString = $Program.UninstallString
            Installed       = $true
        }
        return $ProgramInfo
    }
} # end of Get-TargetResource


function Test-TargetResource {
    [CmdletBinding()]
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet("Present", "Absent")]
        [string]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $InstallerPath,

        [string]
        $ProductId,

        [string]
        $InstalledCheckFilePath,

        [string]
        $InstalledCheckScript,

        [bool]
        $Fuzzy = $false,

        [bool]
        $NoRestart = $false,

        [string]
        $Version,

        [string]
        $Arguments,

        [string]
        $ArgumentsForUninstall,

        [bool]
        $UseUninstallString = $true,

        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [ValidateNotNullOrEmpty()]
        [UInt32[]]
        $ReturnCode = @( 0, 1641, 3010 ),

        [UInt32]
        $TimeoutSec = 900,

        [string]
        $FileHash,

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160')]
        [string]
        $HashAlgorithm = 'SHA256',

        [string]
        $PreAction,

        [string]
        $PostAction,

        [string]
        $PreCopyFrom,

        [string]
        $PreCopyTo
    )

    if ($InstalledCheckScript) {
        $local:scriptBlock = [ScriptBlock]::Create($InstalledCheckScript)
        return [bool]($local:scriptBlock.Invoke())
    }

    $private:GetParam = @{
        Ensure                 = $Ensure
        Name                   = $Name
        InstallerPath          = $InstallerPath
        ProductId              = $ProductId
        InstalledCheckFilePath = $InstalledCheckFilePath
        Fuzzy                  = $Fuzzy
    }

    $ProgramInfo = Get-TargetResource @GetParam -ErrorAction Stop

    if ($Ensure -eq 'Absent') {
        switch ($ProgramInfo.Ensure) {
            'Absent' {
                Write-Verbose ('Match desired state & current state. Return "True"')
                return $true
            }
            'Present' {
                Write-Verbose ('Mismatch desired state & current state. Return "False"')
                return $false
            }
            Default {
                Write-Error 'Test failed (unexpected error)'
            }
        }
    }
    else {
        switch ($ProgramInfo.Ensure) {
            'Absent' {
                Write-Verbose ('Mismatch desired state & current state. Return "False"')
                return $false
            }
            'Present' {
                if ($Version) {
                    if ($Version -ne $ProgramInfo.Version) {
                        Write-Verbose ('The application "{0}" is installed. but NOT match your desired version. (Desired version: "{1}", Installed version: "{2}")' -f $Name, $Version, $ProgramInfo.Version)
                        Write-Verbose ('Mismatch desired state & current state. Return "False"')
                        return $false
                    }
                }

                Write-Verbose ('Match desired state & current state. Return "True"')
                return $true
            }
            Default {
                Write-Error 'Test failed (unexpected error)'
            }
        }
    }
} # end of Test-TargetResource


function Set-TargetResource {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet("Present", "Absent")]
        [string]
        $Ensure = 'Present',

        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $InstallerPath,

        [string]
        $ProductId,

        [string]
        $InstalledCheckFilePath,

        [string]
        $InstalledCheckScript,

        [bool]
        $Fuzzy = $false,

        [bool]
        $NoRestart = $false,

        [string]
        $Version,

        [string]
        $Arguments,

        [string]
        $ArgumentsForUninstall,

        [bool]
        $UseUninstallString = $true,

        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [ValidateNotNullOrEmpty()]
        [UInt32[]]
        $ReturnCode = @( 0, 1641, 3010 ),

        [UInt32]
        $TimeoutSec = 900,

        [string]
        $FileHash,

        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160')]
        [string]
        $HashAlgorithm = 'SHA256',

        [string]
        $PreAction,

        [string]
        $PostAction,

        [string]
        $PreCopyFrom,

        [string]
        $PreCopyTo
    )

    if (($Ensure -eq 'Absent') -and (!$UseUninstallString) -and (!$InstallerPath)) {
        Write-Error ("InstallerPath is not specified. Skip Set-Configuration.")
        return
    }
    elseif (($Ensure -eq 'Present') -and (!$InstallerPath)) {
        Write-Error ("InstallerPath is not specified. Skip Set-Configuration.")
        return
    }

    #PreCopy
    if ([string]::IsNullOrWhiteSpace($PreCopyFrom) -and $PreCopyTo) {
        Write-Warning ('PreCopyTo parameter is specified, but PreCopyFrom is empty. You should specify both PreCopyFrom and PreCopyTo.')
    }
    elseif ($PreCopyFrom -and [string]::IsNullOrWhiteSpace($PreCopyTo)) {
        Write-Warning ('PreCopyFrom parameter is specified, but PreCopyTo is empty. You should specify both PreCopyFrom and PreCopyTo.')
    }
    elseif ($PreCopyFrom -and $PreCopyTo) {
        Write-Verbose ('PreCopy From:"{0}" To:"{1}"' -f $PreCopyFrom, $PreCopyTo)
        Get-RemoteFile -Path $PreCopyFrom -DestinationFolder $PreCopyTo -Credential $Credential -TimeoutSec $TimeoutSec -Force -ErrorAction Stop >$null
    }

    #PreAction
    Invoke-ScriptBlock -ScriptBlockString $PreAction -ErrorAction Continue

    $private:TempFolder = $env:TEMP
    $private:UseWebFile = $false
    $private:Installer = ''
    $private:strInOrUnin = ''
    $private:msiOpt = ''
    $private:Arg = New-Object 'System.Collections.Generic.List[System.String]'
    $private:tmpDriveName = [Guid]::NewGuid()

    try {
        if ($Ensure -eq 'Absent') {
            Write-Verbose ('Ensure = "Absent". Try to uninstall an application.')
            $strInOrUnin = 'Uninstall'
            $msiOpt = 'x'
            $Arguments = $ArgumentsForUninstall

            if ($UseUninstallString) {
                $private:GetParam = @{
                    Ensure        = $Ensure
                    Name          = $Name
                    InstallerPath = $InstallerPath
                    ProductId     = $ProductId
                    Fuzzy         = $Fuzzy
                }
                $private:ProgramInfo = Get-TargetResource @GetParam -ErrorAction Stop

                if (-not $ProgramInfo.UninstallString) {
                    throw ("Couldn't get UninstallString.")
                }

                Write-Verbose ('Use UninstallString for uninstall. ("{0}")' -f $ProgramInfo.UninstallString)
                $UseWebFile = $false
                if ($ProgramInfo.UninstallString -match '^(?<path>.+\.[a-z]{3})(?<args>.*)') {
                    $Installer = $Matches.path
                    $Arg.Add($Matches.args)
                }
                else {
                    throw ("Couldn't parse UninstallString.")
                }
            }
        }
        else {
            Write-Verbose ('Ensure = "Present". Try to install an application.')
            $strInOrUnin = 'Install'
            $msiOpt = 'i'
        }

        if (($Ensure -eq 'Absent') -and $UseUninstallString) {
        }
        else {
            Write-Verbose ('Use Installer ("{0}") for {1}. (if the path of installer as http/https/ftp. will download it)' -f $InstallerPath, $strInOrUnin)
            if ($InstallerPath -match '^msiexec[.exe]?') {
                #[SpecialTreat]If specified 'msiexec.exe', replace 'C:\Windows\System32\msiexec.exe'
                $InstallerPath = (Join-Path $env:windir '\system32\msiexec.exe')
            }
            $private:tmpPath = [System.Uri]$InstallerPath
            if ($tmpPath.IsLoopback -or $tmpPath.IsUnc) {
                Write-Verbose ('"{0}" is local file or remote unc file.' -f $tmpPath.LocalPath)
                $UseWebFile = $false
                if ($PSBoundParameters.Credential) {
                    New-PSDrive -Name $tmpDriveName -PSProvider FileSystem -Root (Split-Path $tmpPath.LocalPath) -Credential $Credential -ErrorAction Stop > $null
                }
                $Installer = $tmpPath.LocalPath
            }
            else {
                $UseWebFile = $true
                $Installer = (Get-RemoteFile -Path $InstallerPath -DestinationFolder $TempFolder -Credential $Credential -TimeoutSec $TimeoutSec -Force -PassThru -ErrorAction Stop)
            }

            if ($FileHash) {
                if (-not (Assert-FileHash -Path $Installer -FileHash $FileHash -Algorithm $HashAlgorithm)) {
                    throw ("File '{0}' does not match expected hash value" -f $Installer)
                }
                else {
                    Write-Verbose ("Hash check passed")
                }
            }
        }

        $Arg.Add($Arguments)
        if (-not (Test-Path $Installer -PathType Leaf)) {
            throw ("Installer file not found. ('{0}')" -f $Installer)
        }

        if ([System.IO.Path]::GetExtension($Installer) -eq '.msi') {
            $Arg.Insert(0, ('/{0} "{1}"' -f $msiOpt, $Installer))
            Write-Verbose ("{2} start. Installer:'{0}', Args:'{1}'" -f 'msiexec.exe', $Arg, $strInOrUnin)
            $ExitCode = Start-Command -FilePath 'msiexec.exe' -ArgumentList $Arg -Timeout ($TimeoutSec * 1000) -ErrorAction Stop
            Write-Verbose ("{1} end. Exitcode: '{0}'" -f $ExitCode, $strInOrUnin)
        }
        else {
            Write-Verbose ("{2} start. Installer:'{0}', Args:'{1}'" -f $Installer, $Arg, $strInOrUnin)
            $ExitCode = Start-Command -FilePath $Installer -ArgumentList $Arg -Timeout ($TimeoutSec * 1000) -ErrorAction Stop
            Write-Verbose ("{1} end. Exitcode: '{0}'" -f $ExitCode, $strInOrUnin)
        }

        if (-not ($ReturnCode -contains $ExitCode)) {
            throw ("The exit code {0} was not expected. Configuration is likely not correct" -f $ExitCode)
        }
        else {
            Write-Verbose ('{0} process exited successfully' -f $strInOrUnin)
        }

        if (-not $NoRestart) {
            $private:serverFeatureData = Invoke-CimMethod -Name 'GetServerFeature' -Namespace 'root\microsoft\windows\servermanager' -Class 'MSFT_ServerManagerTasks' -Arguments @{ BatchSize = 256 } -ErrorAction 'Ignore' -Verbose:$false
            $private:registryData = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction 'Ignore'
            if (($serverFeatureData -and $serverFeatureData.RequiresReboot) -or $registryData -or ($exitcode -eq 3010) -or ($exitcode -eq 1641)) {
                Write-Verbose "The machine requires a reboot"
                $global:DSCMachineStatus = 1
            }
        }
    }
    catch [Exception] {
        Write-Error $_.Exception
    }
    finally {
        if ($PreCopyTo -and (Test-Path $PreCopyTo -ErrorAction SilentlyContinue)) {
            Write-Verbose ("Remove PreCopied file(s)")
            Remove-Item $PreCopyTo -Force -Recurse > $null
        }
        if ($UseWebFile -and $Installer -and (Test-Path $Installer -PathType Leaf -ErrorAction SilentlyContinue)) {
            Write-Verbose ("Remove temp files")
            Remove-Item $Installer -Force -Recurse > $null
        }
        if (Get-PSDrive | Where-Object {$_.Name -eq $tmpDriveName}) {
            Remove-PSDrive -Name $tmpDriveName -Force -ErrorAction SilentlyContinue
        }
    }

    #PostAction
    Invoke-ScriptBlock -ScriptBlockString $PostAction -ErrorAction Continue

} # end of Set-TargetResource


function Get-RemoteFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias("Uri")]
        [Alias("SourcePath")]
        [System.Uri[]] $Path,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$DestinationFolder,

        [Parameter()]
        [AllowNull()]
        [pscredential]$Credential,

        [Parameter()]
        [int]$TimeoutSec = 0,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$PassThru
    )
    begin {
        if (-not (Test-Path $DestinationFolder -PathType Container)) {
            Write-Verbose ('DestinationFolder "{0}" is not exist. Will create it.' -f $DestinationFolder)
            New-Item $DestinationFolder -ItemType Directory -Force -ErrorAction Stop > $null
        }
    }

    Process {
        foreach ($private:tempPath in $Path) {
            try {
                $private:OutFile = ''
                $private:valid = $true
                $private:tmpDriveName = [Guid]::NewGuid()

                if ($null -eq $tempPath.IsLoopback) {
                    $valid = $false
                    throw ("{0} is not valid uri." -f $tempPath)
                }

                # Depending on the location of the installer processing branch (local or shared folder or Web)
                if ($tempPath.IsLoopback -and (!$tempPath.IsUnc)) {
                    # Local file
                    Write-Verbose ('"{0}" is local file.' -f $tempPath.LocalPath)
                    $valid = $true
                    $OutFile = $tempPath.LocalPath
                    Write-Verbose ("Copy file from '{0}' to '{1}'" -f $tempPath.LocalPath, $DestinationFolder)
                    Copy-Item -Path $tempPath.LocalPath -Destination $DestinationFolder -ErrorAction Stop -Force:$Force -Recurse -PassThru:$PassThru
                }
                elseif ($tempPath.IsUnc) {
                    # Shared folder
                    # When using credentials it is necessary to map the drive first
                    if ($PSBoundParameters.Credential) {
                        New-PSDrive -Name $tmpDriveName -PSProvider FileSystem -Root (Split-Path $tempPath.LocalPath) -Credential $Credential -ErrorAction Stop > $null
                    }
                    # Copy to Local
                    $OutFile = Join-Path $DestinationFolder ([System.IO.Path]::GetFileName($tempPath.LocalPath))
                    if (Test-Path $OutFile -PathType Leaf) {
                        if ($tempPath.LocalPath -eq $OutFile) {
                            if ($PassThru) {
                                if (Test-Path $OutFile) {
                                    Get-Item $OutFile
                                }
                            }
                            continue
                        }
                        elseif ($Force) {
                            Write-Warning ('"{0}" will be overwritten.' -f $OutFile)
                        }
                        else {
                            $valid = $false
                            throw ("'{0}' is exist. If you want to replace existing file, Use 'Force' switch." -f $OutFile)
                        }
                    }

                    Write-Verbose ("Copy file from '{0}' to '{1}'" -f $tempPath.LocalPath, $DestinationFolder)
                    Copy-Item -Path $tempPath.LocalPath -Destination $DestinationFolder -ErrorAction Stop -Force:$Force -Recurse
                }
                elseif ($tempPath.Scheme -match 'http|https|ftp') {
                    # Download from Web
                    if ($redUri = Get-RedirectedUrl $tempPath.AbsoluteUri) {
                        # When it is not a file direct link, obtain the file name of the redirect destination(issue #1)
                        $OutFile = Join-Path $DestinationFolder ([System.IO.Path]::GetFileName($redUri.LocalPath))
                    }
                    else {
                        $OutFile = Join-Path $DestinationFolder ([System.IO.Path]::GetFileName($tempPath.LocalPath))
                    }
                    if (Test-Path $OutFile -PathType Leaf) {
                        if ($Force) {
                            Write-Warning ('"{0}" will be overwritten.' -f $OutFile)
                        }
                        else {
                            $valid = $false
                            throw ("'{0}' is exist. If you want to replace existing file, Use 'Force' switch." -f $OutFile)
                        }
                    }

                    Write-Verbose ("Download file from '{0}' to '{1}'" -f $tempPath.AbsoluteUri, $OutFile)
                    $private:origVerbose = $VerbosePreference; $VerbosePreference = 'SilentlyContinue'
                    Invoke-WebRequest -Uri $tempPath.AbsoluteUri -OutFile $OutFile -Credential $Credential -TimeoutSec $TimeoutSec -ErrorAction stop
                    $VerbosePreference = $origVerbose
                }
                else {
                    $valid = $false
                    throw ("{0} is not valid uri." -f $tempPath)
                }

                if ($valid -and $OutFile -and $PassThru) {
                    if (Test-Path $OutFile) {
                        Get-Item $OutFile
                    }
                }
            }
            catch [Exception] {
                Write-Error $_.Exception
            }
            finally {
                if (Get-PSDrive | Where-Object {$_.Name -eq $tmpDriveName}) {
                    Remove-PSDrive -Name $tmpDriveName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}


function Assert-FileHash {
    [CmdletBinding()]
    [OutputType([bool])]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FileHash,

        [Parameter()]
        [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'RIPEMD160')]
        [string]
        $Algorithm = 'SHA256'
    )

    Process {
        $private:hash = Get-FileHash -Path $Path -Algorithm $Algorithm | Select-Object Hash
        if ($FileHash -eq $hash.Hash) {
            Write-Verbose ('Match file hash of "{1}". ({0})' -f $hash.Hash, $Path)
            return $true
        }
        else {
            Write-Verbose ('Not match file hash of "{1}". ({0})' -f $hash.Hash, $Path)
            return $false
        }
    }
}


function Get-InstalledProgram {
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'Name')]
        [string] $Name,

        [Parameter(Mandatory, ParameterSetName = 'Id')]
        [string] $ProductId,

        [Parameter(ParameterSetName = 'Name')]
        [switch] $Fuzzy,

        [switch] $Wow64,

        [switch] $FallbackToWow64 = $true
    )

    $local:Program = $null
    switch ($Wow64) {
        $true {
            $UninstallRegMachine = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            $UninstallRegUser = "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        }

        $false {
            $UninstallRegMachine = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            $UninstallRegUser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        }
    }

    $local:InstalledPrograms = @()
    $local:InstalledPrograms += Get-ChildItem $UninstallRegMachine | ForEach-Object {Get-ItemProperty $_.PSPath} | Where-Object {$_.DisplayName}
    if (Test-Path $UninstallRegUser) {
        $local:InstalledPrograms += Get-ChildItem $UninstallRegUser | ForEach-Object {Get-ItemProperty $_.PSPath} | Where-Object {$_.DisplayName}
    }

    switch ($PsCmdlet.ParameterSetName) {
        'Name' {
            if ($Fuzzy) {
                $Program = $InstalledPrograms | Where-Object {$_.DisplayName -match $Name} | Select-Object -First 1
            }
            else {
                $Program = $InstalledPrograms | Where-Object {$_.DisplayName -eq $Name} | Select-Object -First 1
            }
            break
        }
        'Id' {
            $ProductId = Format-ProductId -ProductId $ProductId
            $Program = $InstalledPrograms | Where-Object {$_.PSChildName -eq $ProductId} | Select-Object -First 1
            break
        }
    }

    if ($Program) {
        $Program
    }
    elseif ((!$Wow64) -and $FallbackToWow64 -and (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")) {
        Get-InstalledProgram @PSBoundParameters -Wow64
    }
}


function Format-ProductId {
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ProductId
    )

    try {
        $private:identifyingNumber = "{{{0}}}" -f [Guid]::Parse($ProductId).ToString().ToUpper()
        return $identifyingNumber
    }
    catch {
        Write-Error ("The specified ProductId ({0}) is not a valid Guid" -f $ProductId)
    }
}


function Invoke-ScriptBlock {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string]$ScriptBlockString,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Arguments
    )

    if (-not $ScriptBlockString) { return }

    try {
        $scriptBlock = [ScriptBlock]::Create($ScriptBlockString).GetNewClosure()
        Write-Verbose ('Execute ScriptBlock')
        if (@($Arguments).Count -ge 1) {
            $scriptBlock.Invoke($Arguments) | Out-String -Stream | Write-Verbose
        }
        else {
            $scriptBlock.Invoke() | Out-String -Stream | Write-Verbose
        }
    }
    catch {
        throw $_
    }
}


function Get-RedirectedUrl {
    Param (
        [Parameter(Mandatory, Position = 0)]
        [string]$URL
    )

    $request = [System.Net.WebRequest]::Create($URL)
    $request.AllowAutoRedirect = $false
    $response = $request.GetResponse()

    If ($response.StatusCode -eq "Found") {
        [System.Uri]$response.GetResponseHeader("Location")
    }
}


function Start-Command {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [string] $FilePath,

        [Parameter(Position = 1)]
        [string[]]$ArgumentList,

        [int]$Timeout = [int]::MaxValue
    )
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $FilePath
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = [string]$ArgumentList
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() > $null
    if (!$Process.WaitForExit($Timeout)) {
        $Process.Kill()
        Write-Error ('Process timeout. Terminated. (Timeout:{0}s, Process:{1})' -f ($Timeout * 0.001), $FilePath)
    }
    $Process.ExitCode
}

Export-ModuleMember -Function *-TargetResource
