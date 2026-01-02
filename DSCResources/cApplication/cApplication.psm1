Enum Ensure{
    Absent
    Present
}

Enum LogLevel{
    None = 0
    Minimal = 8
    Moderate = 64
    All = 256
}

function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Present', 'Absent')]
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
        $Fuzzy = $false,

        [LogLevel]
        $LogLevel = [LogLevel]::All
    )

    $global:GlobalLogLevel = $LogLevel

    # Get Application info
    # $InstalledCheckFilePath has highest priority
    if ($InstalledCheckFilePath) {
        Write-MyVerbose -Message ('InstalledCheckFilePath is specified. Whether an application exists or not is judged by whether or not the path exists.') -LogLevel Minimal
        if (Test-Path -Path $InstalledCheckFilePath) {
            Write-MyVerbose -Message ('"{0}" exists.' -f $InstalledCheckFilePath) -LogLevel Moderate
            $Program = @{
                DisplayName = $Name
            }
        }
        else {
            Write-MyVerbose -Message ('"{0}" does not exist.' -f $InstalledCheckFilePath) -LogLevel Moderate
            $Program = $null
        }
    }
    # $ProductId takes priority over $Name
    elseif ($ProductId) {
        $Program = Get-InstalledProgram -ProductId $ProductId
    }
    else {
        $Program = Get-InstalledProgram -Name $Name -Fuzzy:$Fuzzy
    }

    if (-not $Program) {
        Write-MyVerbose -Message ('The application "{0}" is not installed.' -f $Name) -LogLevel Minimal
        $returnValue = @{
            Ensure        = [Ensure]::Absent
            Name          = ''
            InstallerPath = $InstallerPath
            Installed     = $false
        }
        return $returnValue
    }
    else {
        Write-MyVerbose -Message ('The application "{0}" is installed.' -f $Program.DisplayName) -LogLevel Minimal
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
        [ValidateSet('Present', 'Absent')]
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

        [bool]
        $UseSemVer = $false,

        [string]
        $Arguments,

        [string]
        $ArgumentsForUninstall,

        [string]
        $WorkingDirectory,

        [bool]
        $UseUninstallString = $false,

        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [ValidateNotNullOrEmpty()]
        [UInt32[]]
        $ReturnCode = @( 0, 1641, 3010 ),

        [UInt32]
        [ValidateRange(0, 2147483)]
        $ProcessTimeout = 2147483,

        [UInt32]
        [ValidateRange(0, 2147483647)]
        $DownloadTimeout = 900,

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
        $PreCopyTo,

        [LogLevel]
        $LogLevel = [LogLevel]::All
    )

    $global:GlobalLogLevel = $LogLevel

    if ($InstalledCheckScript) {
        Write-MyVerbose -Message ('InstalledCheckScript is specified. Whether an application exists or not is judged by script invocation.') -LogLevel Minimal
        $local:scriptBlock = [ScriptBlock]::Create($InstalledCheckScript)
        $ScriptResult = [bool]($local:scriptBlock.Invoke())
        if ($ScriptResult) {
            Write-MyVerbose -Message ('Match desired state & current state. Return "True"') -LogLevel Minimal
        }
        else {
            Write-MyVerbose -Message ('Mismatch desired state & current state. Return "False"') -LogLevel Minimal
        }
        return $ScriptResult
    }

    $private:GetParam = @{
        Ensure                 = $Ensure
        Name                   = $Name
        InstallerPath          = $InstallerPath
        ProductId              = $ProductId
        InstalledCheckFilePath = $InstalledCheckFilePath
        Fuzzy                  = $Fuzzy
        LogLevel               = $LogLevel
    }

    $ProgramInfo = Get-TargetResource @GetParam -ErrorAction Stop

    if ($Ensure -eq 'Absent') {
        switch ($ProgramInfo.Ensure) {
            'Absent' {
                Write-MyVerbose -Message ('Match desired state & current state. Return "True"') -LogLevel Minimal
                return $true
            }
            'Present' {
                Write-MyVerbose -Message ('Mismatch desired state & current state. Return "False"') -LogLevel Minimal
                return $false
            }
            Default {
                Write-Error -Message 'Test failed (unexpected error)'
            }
        }
    }
    else {
        switch ($ProgramInfo.Ensure) {
            'Absent' {
                Write-MyVerbose -Message ('Mismatch desired state & current state. Return "False"') -LogLevel Minimal
                return $false
            }
            'Present' {
                if ($Version) {
                    if ($UseSemVer) {
                        $null = Load-SemVer
                        $SemVer = $null
                        if (-not [pspm.SemVer]::TryParse($ProgramInfo.Version, [ref]$SemVer)) {
                            Write-Error -Message 'The version number of this application does not follow the Semantic Versioning specification.'
                        }
                        else {
                            try {
                                $Range = [pspm.SemVerRange]::new($Version)
                                if (-not $Range.IsSatisfied($SemVer)) {
                                    Write-MyVerbose -Message ('The application "{0}" is installed but does not match your desired version. (Desired version: "{1}", Installed version: "{2}")' -f $Name, $Version, $ProgramInfo.Version) -LogLevel Moderate
                                    Write-MyVerbose -Message ('Mismatch desired state and current state. Return "False".') -LogLevel Minimal
                                    return $false
                                }
                            }
                            catch {
                                Write-Error -Exception $_.Exception
                            }
                        }
                    }
                    else {
                        if ($Version -ne $ProgramInfo.Version) {
                            Write-MyVerbose -Message ('The application "{0}" is installed but does not match your desired version. (Desired version: "{1}", Installed version: "{2}")' -f $Name, $Version, $ProgramInfo.Version) -LogLevel Moderate
                            Write-MyVerbose -Message ('Mismatch desired state and current state. Return "False".') -LogLevel Minimal
                            return $false
                        }
                    }
                }

                Write-MyVerbose -Message ('Match desired state & current state. Return "True"') -LogLevel Minimal
                return $true
            }
            Default {
                Write-Error -Message 'Test failed (unexpected error)'
            }
        }
    }
} # end of Test-TargetResource


function Set-TargetResource {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Present', 'Absent')]
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

        [bool]
        $UseSemVer = $false,

        [string]
        $Arguments,

        [string]
        $ArgumentsForUninstall,

        [string]
        $WorkingDirectory,

        [bool]
        $UseUninstallString = $false,

        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        # Return codes 1641 and 3010 indicate success when a restart is requested per installation
        [ValidateNotNullOrEmpty()]
        [UInt32[]]
        $ReturnCode = @( 0, 1641, 3010 ),

        [UInt32]
        [ValidateRange(0, 2147483)]
        $ProcessTimeout = 2147483, #seconds

        [UInt32]
        [ValidateRange(0, 2147483647)]
        $DownloadTimeout = 900, #seconds

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
        $PreCopyTo,

        [LogLevel]
        $LogLevel = [LogLevel]::All
    )

    $global:GlobalLogLevel = $LogLevel

    if (($Ensure -eq 'Absent') -and (!$UseUninstallString) -and (!$InstallerPath)) {
        Write-Error -Message ('InstallerPath is not specified. Skip Set-Configuration.')
        return
    }
    elseif (($Ensure -eq 'Present') -and (!$InstallerPath)) {
        Write-Error -Message ('InstallerPath is not specified. Skip Set-Configuration.')
        return
    }

    #PreCopy
    if ([string]::IsNullOrWhiteSpace($PreCopyFrom) -and $PreCopyTo) {
        Write-Warning -Message ('PreCopyTo parameter is specified, but PreCopyFrom is empty. You should specify both PreCopyFrom and PreCopyTo.')
    }
    elseif ($PreCopyFrom -and [string]::IsNullOrWhiteSpace($PreCopyTo)) {
        Write-Warning -Message ('PreCopyFrom parameter is specified, but PreCopyTo is empty. You should specify both PreCopyFrom and PreCopyTo.')
    }
    elseif ($PreCopyFrom -and $PreCopyTo) {
        Write-MyVerbose -Message ('PreCopy from "{0}" to "{1}".' -f $PreCopyFrom, $PreCopyTo) -LogLevel All
        Get-RemoteFile -Path $PreCopyFrom -DestinationFolder $PreCopyTo -Credential $Credential -TimeoutSec $DownloadTimeout -Force -ErrorAction Stop >$null
    }

    #PreAction
    try {
        Invoke-ScriptBlock -ScriptBlockString $PreAction
    }
    catch [Exception] {
        Write-Error -Exception $_.Exception
    }

    $private:TempFolder = $env:TEMP
    $private:UseWebFile = $false
    $private:Installer = ''
    $private:strInOrUnin = ''
    $private:msiOpt = ''
    $private:Arg = New-Object 'System.Collections.Generic.List[System.String]'
    $private:tmpDriveName = [Guid]::NewGuid()

    try {
        if ($Ensure -eq 'Absent') {
            Write-MyVerbose -Message ('Ensure = "Absent". Try to uninstall an application.') -LogLevel Minimal
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

                Write-MyVerbose -Message ('Use UninstallString for uninstall. ("{0}")' -f $ProgramInfo.UninstallString) -LogLevel Moderate
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
            Write-MyVerbose -Message ('Ensure = "Present". Try to install an application.') -LogLevel Minimal
            $strInOrUnin = 'Install'
            $msiOpt = 'i'
        }

        if (($Ensure -eq 'Absent') -and $UseUninstallString) {
        }
        else {
            Write-MyVerbose -Message ('Use installer ("{0}") for {1}. (If the path of an installer is http/https/ftp, it will download it.)' -f $InstallerPath, $strInOrUnin) -LogLevel All
            if ($InstallerPath -match '^msiexec[.exe]?') {
                #[SpecialTreat]If 'msiexec.exe' is specified, replace with 'C:\Windows\System32\msiexec.exe'
                $InstallerPath = (Join-Path -Path $env:windir -ChildPath '\system32\msiexec.exe')
            }
            $private:tmpPath = [System.Uri]$InstallerPath
            if ($tmpPath.IsLoopback -or $tmpPath.IsUnc) {
                Write-MyVerbose -Message ('"{0}" is a local file or remote UNC file.' -f $tmpPath.LocalPath) -LogLevel All
                $UseWebFile = $false
                if ($PSBoundParameters.Credential) {
                    New-PSDrive -Name $tmpDriveName -PSProvider FileSystem -Root (Split-Path $tmpPath.LocalPath) -Credential $Credential -ErrorAction Stop > $null
                }
                $Installer = $tmpPath.LocalPath
            }
            else {
                $UseWebFile = $true
                $Installer = (Get-RemoteFile -Path $InstallerPath -DestinationFolder $TempFolder -Credential $Credential -TimeoutSec $DownloadTimeout -Force -PassThru -ErrorAction Stop)
                $DownloadedFile = $Installer
            }

            if ($FileHash) {
                if (-not (Assert-FileHash -Path $Installer -FileHash $FileHash -Algorithm $HashAlgorithm)) {
                    throw ("File '{0}' does not match expected hash value." -f $Installer)
                }
                else {
                    Write-MyVerbose -Message ('Hash check passed.') -LogLevel Moderate
                }
            }
        }

        $Arg.Add($Arguments)
        if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
            throw ("Installer file not found. ('{0}')" -f $Installer)
        }

        if ([System.IO.Path]::GetExtension($Installer) -eq '.msi') {
            $Arg.Insert(0, ('/{0} "{1}"' -f $msiOpt, $Installer))
            $Installer = 'msiexec.exe'
        }

        $CommandParam = @{
            FilePath     = $Installer
            ArgumentList = $Arg
            Timeout      = $ProcessTimeout * 1000
        }
        if ($WorkingDirectory) {
            $CommandParam.WorkingDirectory = $WorkingDirectory
            Write-MyVerbose -Message ("{2} start. Installer:'{0}', Args:'{1}', WorkDir:'{3}'" -f $Installer, $Arg, $strInOrUnin, $WorkingDirectory) -LogLevel All
        }
        else {
            Write-MyVerbose -Message ("{2} start. Installer:'{0}', Args:'{1}'" -f $Installer, $Arg, $strInOrUnin) -LogLevel All
        }
        $ExitCode = Start-Command @CommandParam -ErrorAction Stop
        Write-MyVerbose -Message ("{1} end. ExitCode: '{0}'" -f $ExitCode, $strInOrUnin) -LogLevel Moderate

        if (-not ($ReturnCode -contains $ExitCode)) {
            throw ('The exit code {0} was not expected. Configuration is likely not correct.' -f $ExitCode)
        }
        else {
            Write-MyVerbose -Message ('{0} process exited successfully.' -f $strInOrUnin) -LogLevel Minimal
        }

        if (-not $NoRestart) {
            $private:serverFeatureData = Invoke-CimMethod -Name 'GetServerFeature' -Namespace 'root\microsoft\windows\servermanager' -Class 'MSFT_ServerManagerTasks' -Arguments @{ BatchSize = 256 } -ErrorAction 'Ignore' -Verbose:$false
            $private:registryData = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction 'Ignore'
            if (($serverFeatureData -and $serverFeatureData.RequiresReboot) -or $registryData -or ($exitcode -eq 3010) -or ($exitcode -eq 1641)) {
                Write-MyVerbose -Message 'The machine requires a reboot.' -LogLevel Minimal
                $global:DSCMachineStatus = 1
            }
        }
    }
    catch [Exception] {
        Write-Error -Exception $_.Exception
    }
    finally {
        if ($PreCopyTo -and (Test-Path $PreCopyTo -ErrorAction SilentlyContinue)) {
            Write-MyVerbose -Message ('Remove PreCopied file(s)') -LogLevel Moderate
            Remove-Item -LiteralPath $PreCopyTo -Force -Recurse > $null
        }
        if ($UseWebFile -and $DownloadedFile -and (Test-Path $DownloadedFile -PathType Leaf -ErrorAction SilentlyContinue)) {
            Write-MyVerbose -Message ('Remove temp files.') -LogLevel Moderate
            Remove-Item -LiteralPath $DownloadedFile -Force -Recurse > $null
        }
        if (Get-PSDrive | Where-Object -FilterScript { $_.Name -eq $tmpDriveName }) {
            Remove-PSDrive -Name $tmpDriveName -Force -ErrorAction SilentlyContinue
        }
    }

    #PostAction
    try {
        Invoke-ScriptBlock -ScriptBlockString $PostAction
    }
    catch [Exception] {
        Write-Error -Exception $_.Exception
    }

} # end of Set-TargetResource


function Get-RemoteFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('Uri')]
        [Alias('SourcePath')]
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
            Write-MyVerbose -Message ('DestinationFolder "{0}" does not exist. Will create it.' -f $DestinationFolder) -LogLevel All
            New-Item -Path $DestinationFolder -ItemType Directory -Force -ErrorAction Stop > $null
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
                    throw ('{0} is not a valid URI.' -f $tempPath)
                }

                # Depending on the location of the installer processing branch (local or shared folder or web)
                if ($tempPath.IsLoopback -and (!$tempPath.IsUnc)) {
                    # Local file
                    Write-MyVerbose -Message ('"{0}" is a local file.' -f $tempPath.LocalPath) -LogLevel All
                    $valid = $true
                    $OutFile = $tempPath.LocalPath
                    Write-MyVerbose -Message ("Copy file from '{0}' to '{1}'." -f $tempPath.LocalPath, $DestinationFolder) -LogLevel All
                    Copy-Item -Path $tempPath.LocalPath -Destination $DestinationFolder -ErrorAction Stop -Force:$Force -Recurse -PassThru:$PassThru
                }
                elseif ($tempPath.IsUnc) {
                    # Shared folder
                    # When using credentials, it is necessary to map the drive first
                    if ($PSBoundParameters.Credential) {
                        New-PSDrive -Name $tmpDriveName -PSProvider FileSystem -Root (Split-Path $tempPath.LocalPath) -Credential $Credential -ErrorAction Stop > $null
                    }
                    # Copy to local
                    $OutFile = Join-Path -Path $DestinationFolder -ChildPath ([System.IO.Path]::GetFileName($tempPath.LocalPath))
                    if (Test-Path -LiteralPath $OutFile -PathType Leaf) {
                        if ($tempPath.LocalPath -eq $OutFile) {
                            if ($PassThru) {
                                if (Test-Path -LiteralPath $OutFile) {
                                    Get-Item -LiteralPath $OutFile
                                }
                            }
                            continue
                        }
                        elseif ($Force) {
                            Write-Warning -Message ('"{0}" will be overwritten.' -f $OutFile)
                        }
                        else {
                            $valid = $false
                            throw ("'{0}' exists. If you want to replace the existing file, use the 'Force' switch." -f $OutFile)
                        }
                    }

                    Write-MyVerbose -Message ("Copy file from '{0}' to '{1}'" -f $tempPath.LocalPath, $DestinationFolder) -LogLevel All
                    Copy-Item -Path $tempPath.LocalPath -Destination $DestinationFolder -ErrorAction Stop -Force:$Force -Recurse
                }
                elseif ($tempPath.Scheme -match 'http|https|ftp') {
                    # Download from web
                    Enable-TLS12
                    $Proxy = Get-ProxySetting -TargetUrl $tempPath.AbsoluteUri -ErrorAction Ignore

                    # When it is not a direct file link, obtain the file name of the redirect destination (issue #1)
                    $OutFileName = [System.IO.Path]::GetFileName($tempPath.LocalPath)
                    if (-not [System.IO.Path]::GetExtension($OutFileName)) {
                        $RealFileName = Get-RedirectedFilename -URL $tempPath.AbsoluteUri -Proxy $Proxy -ErrorAction Ignore
                        if ([System.IO.Path]::GetExtension($RealFileName)) {
                            $OutFileName = $RealFileName
                        }
                    }

                    if ($OutFileName -eq '') {
                        $OutFileName = [System.IO.Path]::GetRandomFileName()
                    }

                    $OutFile = Join-Path -Path $DestinationFolder -ChildPath $OutFileName
                    if (Test-Path -LiteralPath $OutFile -PathType Leaf) {
                        if ($Force) {
                            Write-Warning -Message ('"{0}" will be overwritten.' -f $OutFile)
                        }
                        else {
                            $valid = $false
                            throw ("'{0}' exists. If you want to replace the existing file, use the 'Force' switch." -f $OutFile)
                        }
                    }

                    Write-MyVerbose -Message ("Download file from '{0}' to '{1}'." -f $tempPath.AbsoluteUri, $OutFile) -LogLevel All
                    #Suppress progress bar for faster download
                    $private:origProgress = $ProgressPreference
                    $ProgressPreference = 'SilentlyContinue'
                    Invoke-WebRequest -Uri $tempPath.AbsoluteUri -OutFile $OutFile -Credential $Credential -Proxy $Proxy.Address -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction stop
                    $ProgressPreference = $private:origProgress
                }
                else {
                    $valid = $false
                    throw ('{0} is not a valid URI.' -f $tempPath)
                }

                if ($valid -and $OutFile -and $PassThru) {
                    if (Test-Path -LiteralPath $OutFile) {
                        Get-Item -LiteralPath $OutFile
                    }
                }
            }
            catch [Exception] {
                Write-Error -Exception $_.Exception
            }
            finally {
                if (Get-PSDrive | Where-Object -FilterScript { $_.Name -eq $tmpDriveName }) {
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
        $private:hash = Get-FileHash -Path $Path -Algorithm $Algorithm | Select-Object -Property Hash
        if ($FileHash -eq $hash.Hash) {
            Write-MyVerbose -Message ('Match file hash of "{1}". ({0})' -f $hash.Hash, $Path) -LogLevel All
            return $true
        }
        else {
            Write-MyVerbose -Message ('Not match file hash of "{1}". ({0})' -f $hash.Hash, $Path) -LogLevel All
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
            $UninstallRegMachine = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            $UninstallRegUser = 'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        }

        $false {
            $UninstallRegMachine = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            $UninstallRegUser = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        }
    }

    $local:InstalledPrograms = @()
    $local:InstalledPrograms += Get-ChildItem -LiteralPath $UninstallRegMachine | ForEach-Object -Process { Get-ItemProperty -LiteralPath $_.PSPath } | Where-Object -FilterScript { $_.DisplayName }
    if (Test-Path $UninstallRegUser) {
        $local:InstalledPrograms += Get-ChildItem -LiteralPath $UninstallRegUser | ForEach-Object -Process { Get-ItemProperty -LiteralPath $_.PSPath } | Where-Object -FilterScript { $_.DisplayName }
    }

    switch ($PsCmdlet.ParameterSetName) {
        'Name' {
            if ($Fuzzy) {
                $Program = $InstalledPrograms | Where-Object -FilterScript { $_.DisplayName -match $Name } | Select-Object -First 1
            }
            else {
                $Program = $InstalledPrograms | Where-Object -FilterScript { $_.DisplayName -eq $Name } | Select-Object -First 1
            }
            break
        }
        'Id' {
            $ProductId = Format-ProductId -ProductId $ProductId
            $Program = $InstalledPrograms | Where-Object -FilterScript { $_.PSChildName -eq $ProductId } | Select-Object -First 1
            break
        }
    }

    if ($Program) {
        $Program
    }
    elseif ((!$Wow64) -and $FallbackToWow64 -and (Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
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
        $private:identifyingNumber = '{{{0}}}' -f [Guid]::Parse($ProductId).ToString().ToUpper()
        return $identifyingNumber
    }
    catch {
        Write-Error -Message ('The specified ProductId ({0}) is not a valid GUID.' -f $ProductId)
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
        Write-MyVerbose -Message ('Execute ScriptBlock') -LogLevel Moderate
        if (@($Arguments).Count -ge 1) {
            $scriptBlock.Invoke($Arguments) | Out-String -Stream | Write-MyVerbose -LogLevel All
        }
        else {
            $scriptBlock.Invoke() | Out-String -Stream | Write-MyVerbose -LogLevel All
        }
    }
    catch {
        throw $_
    }
}


function Get-RedirectedFilename {
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(Mandatory, Position = 0)]
        [string]$URL,

        [Parameter()]
        [AllowNull()]
        [System.Net.IWebProxy]$Proxy
    )

    $fileName = ''

    try {
        $request = [System.Net.WebRequest]::Create($URL)
        if ($null -ne $Proxy) {
            $request.Proxy = $Proxy
        }
        $request.AllowAutoRedirect = $true
        $request.Method = 'HEAD'
        $response = $request.GetResponse()

        if ($cd = $response.GetResponseHeader('Content-Disposition')) {
            try {
                $contentDisposition = [System.Net.Http.Headers.ContentDispositionHeaderValue]::Parse($cd)
            }
            catch {}
            if ($contentDisposition.FileNameStar) {
                $fileName = [System.IO.Path]::GetFileName($contentDisposition.FileNameStar)
            }
            elseif ($contentDisposition.FileName) {
                $fileName = [System.IO.Path]::GetFileName($contentDisposition.FileName)
            }
        }
        else {
            $fileName = [System.IO.Path]::GetFileName($response.ResponseUri.LocalPath)
        }

        $fileName.Trim()
    }
    catch {
        Write-Error -Exception $_.Exception
    }
    finally {
        if ($response) {
            $response.Close()
        }
    }
}


function Start-Command {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0)]
        [string] $FilePath,

        [Parameter(Position = 1)]
        [string[]]$ArgumentList,

        [Parameter()]
        [string]$WorkingDirectory,

        [Parameter()]
        [int]$Timeout = [int]::MaxValue #milliseconds
    )
    $ProcessInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $FilePath
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = [string]$ArgumentList
    if ($PSBoundParameters.ContainsKey('WorkingDirectory')) {
        if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
            Write-Warning -Message ('Specified working directory path does not exist.')
        }
        else {
            $ProcessInfo.WorkingDirectory = $WorkingDirectory
        }
    }
    $Process = New-Object -TypeName System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() > $null
    if (!$Process.WaitForExit($Timeout)) {
        $Process.Kill()
        Write-Warning -Message ('Process timeout. Terminated. (Timeout:{0}s, Process:{1})' -f ($Timeout * 0.001), $FilePath)
        # Return timeout error code 0x000005B4
        1460
    }
    else {
        $Process.ExitCode
    }
}


function Enable-TLS12 {
    # Enable TLS1.2 in the current session (only if it has not been enabled)
    try {
        if (([Net.ServicePointManager]::SecurityProtocol -ne [Net.SecurityProtocolType]::SystemDefault) -and (-not ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12))) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
    }
    catch {
        # Ignore all exceptions
    }
}


function Load-SemVer {
    $SemVerDllPath = Join-Path $PSScriptRoot '..\..\Libs\SemVer\SemVer.dll'
    if (-not ('pspm.SemVer' -as [Type])) {
        if (Test-Path -LiteralPath $SemVerDllPath -PathType Leaf) {
            Add-Type -LiteralPath $SemVerDllPath -ErrorAction Stop
        }
    }
}


function Get-ProxySetting {
    [CmdletBinding()]
    [OutputType([System.Net.WebProxy])]
    param (
        [Parameter(Mandatory = $false)]
        [uri]$TargetUrl
    )

    # Proxy detection priority
    # 0. Environment variable (http_proxy)
    # 1. IE (GetSystemWebProxy)
    # 2. WinHTTP (WinHttpGetDefaultProxyConfiguration)

    $Proxy = $null

    # 0. Environment Variable
    if ($env:http_proxy) {
        try {
            $Proxy = [System.Net.WebProxy]::new($env:http_proxy)
        }
        catch [System.UriFormatException] {
            Write-Error -Message ('Invalid proxy setting detected. The environment variable "http_proxy" is {0}.' -f $env:http_proxy)
        }
        catch {
            Write-Error -Exception $_.Exception
        }
    }

    if ($Proxy) {
        Write-MyVerbose -Message 'Find proxy setting in environment variable "http_proxy".' -LogLevel All
        return $Proxy
    }

    # 1. IE
    if (-not $TargetUrl) { $TargetUrl = 'http://example.com' }
    $webProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    if (($null -ne $webProxy) -and (-not $webProxy.IsBypassed($TargetUrl))) {
        $Proxy = try { [System.Net.WebProxy]::new($webProxy.GetProxy($TargetUrl), $false) }catch { Write-Error -ErrorAction $_.exception }
    }

    if ($Proxy) {
        Write-MyVerbose -Message 'Find proxy setting in Internet Explorer preferences.' -LogLevel All
        return $Proxy
    }

    # 2.WinHTTP
    # Original code is written by itn3000 https://gist.github.com/itn3000/b414da5337b7d229d812ec3ddcffb446
    if (-not ('WinHttp' -as [Type])) {
        $CSharpCode = @'
using System.Runtime.InteropServices;
public enum WinHttpAccessType
{
    DefaultProxy = 0,
    NamedProxy = 3,
    NoProxy = 1
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WINHTTP_PROXY_INFO
{
    public WinHttpAccessType AccessType;
    public string Proxy;
    public string Bypass;
}
public class WinHttp
{
    [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool WinHttpGetDefaultProxyConfiguration(ref WINHTTP_PROXY_INFO config);
}
'@
        $null = Add-Type -TypeDefinition $CSharpCode -Language CSharp
    }
    $winHTTPProxy = New-Object WINHTTP_PROXY_INFO
    $winHTTPProxy.AccessType = [WinHttpAccessType]::DefaultProxy
    $null = [WinHttp]::WinHttpGetDefaultProxyConfiguration([ref]$winHTTPProxy)

    if ($winHTTPProxy.AccessType -eq [WinHttpAccessType]::NamedProxy) {
        $bypassLocal = $false
        if (-not [string]::IsNullOrEmpty($winHTTPProxy.Bypass)) {
            $BypassList = New-Object 'System.Collections.Generic.List[string]'
            @($winHTTPProxy.Bypass -split ';').ForEach( {
                    if ($_ -eq '<local>') {
                        $bypassLocal = $true
                    }
                    else {
                        $s = [regex]::Replace($_, '([$^\|.{}\[\]()+\\])', '\$1')
                        $s = [regex]::Replace($s, '\*', '.*')
                        $s = [regex]::Replace($s, '\?', '.')
                        $BypassList.Add($s)
                    }
                })
            $Proxy = try { [System.Net.WebProxy]::new($winHTTPProxy.Proxy, $bypassLocal, $BypassList.ToArray()) }catch { Write-Error -ErrorAction $_.exception }
        }
        else {
            $Proxy = try { [System.Net.WebProxy]::new($winHTTPProxy.Proxy, $bypassLocal) }catch { Write-Error -ErrorAction $_.exception }
        }
    }

    if ($Proxy) {
        Write-MyVerbose -Message 'Find proxy setting in WinHTTP.' -LogLevel All
        return $Proxy
    }
}

function Write-MyVerbose {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [Alias('Msg')]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter()]
        [LogLevel]$LogLevel = [LogLevel]::All
    )

    begin {
        if (($null -eq $global:GlobalLogLevel) -or ($LogLevel -le $global:GlobalLogLevel)) {
            $ShouldInvoke = $true
        }
        else {
            $ShouldInvoke = $false
        }

        if ($ShouldInvoke) {
            $WriteVerboseParams = [System.Collections.Generic.Dictionary[[String], [Object]]]::new($PSBoundParameters)
            $null = $WriteVerboseParams.Remove('LogLevel')
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Write-Verbose', [System.Management.Automation.CommandTypes]::Cmdlet)
            $scriptCmd = { & $wrappedCmd @WriteVerboseParams }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
        }
    }

    process {
        if ($ShouldInvoke) {
            $steppablePipeline.Process($_)
        }
    }

    end {
        if ($ShouldInvoke) {
            $steppablePipeline.End()
        }
    }
}

Export-ModuleMember -Function *-TargetResource
