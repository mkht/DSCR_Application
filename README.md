DSCR_Application
====

PowerShell DSC Resource to Install / Uninstall Windows Desktop Applications.

## Install
You can install Resource through [PowerShell Gallery](https://www.powershellgallery.com/packages/DSCR_Application/).
```Powershell
Install-Module -Name DSCR_Application
```

## Resources
* **cApplication**
DSC Resource to Install / Uninstall Windows Desktop Applications. It is easier to use and more flexible compared to the built-in "Package" resource.

## Properties

There are many properties, but most are optional.
You can use this resource simply or flexibly. Please see the "Examples" section below.

### cApplication
+ **[string] Ensure** (Write):
    + Specifies whether or not the application should be installed or not.
    + The default value is Present. { Present | Absent }.

+ **[string] Name** (key):
    + The name of the application that should be installed or uninstalled. You can confirm an accurate name of the application from "Programs and Features" in the control panel.

+ **[bool] Fuzzy** (Write):
    + If specified this property as `$true`, you can use regular expressions in the `Name` property. 
    + The default value is `$false`.
    + :warning: Be careful that the RegExp matches only one application.

+ **[string] ProductId** (Write): 
    + The GUID of the application.
    + This is the optional parameter. If this property is specified, the `Name` property will be ignored.

+ **[string] Version** (Write): 
    + Indicates the expected version string of the application.
    + When the property not specified, This resource simply tests whether the application is installed or not. But when specified, This also tests the installed version is match the expected one.

+ **[string] InstallerPath** (Required):
    + The path to the installer or uninstaller file.
    + You can use Local file / UNC / http / https / ftp . (if specified http/https/ftp. the file will be downloaded to temp dir before installation)

+ **[PSCredential] Credential** (Write):
    + The credential for access to the installer on a remote source if needed.
    + :warning: If you want to run the installation as specific user, you need to use `RunAsCredential` standard property.

+ **[UInt32] TimeoutSec** (Write):
    + The timeout secs of download the installer from http/https/ftp.
    + The default value is 900. (0 is infinite)

+ **[string] FileHash** (Write):
    + The expected hash value of the installer file at the given path.
    + This is the optional parameter. Hash will be tested only when the param specified.

+ **[string] HashAlgorithm** (Write):
    + The algorithm used to generate the given hash value.
    + The default value is SHA256 { SHA1 | SHA256 | SHA384 | SHA512 | MD5 | RIPEMD160 }

+ **[string] Arguments** (Write): 
    + The arguments to be passed to the installer during installation if needed.

+ **[string] ArgumentsForUninstall** (Write): 
    + The arguments to be passed to the uninstaller during uninstallation if needed.

+ **[bool] UseUninstallString** (Write): 
    + If specified this property as `$true`, This resource will use the standard uninstall method that is registered in the registry value of "UninstallString" to uninstall programs.
    + The default value is `$false`.
    + If specified as `$true`, `InstallerPath` and `ArgumentsForUninstall` will be ignored.

+ **[UInt32[]] ReturnCode** (Write): 
    + Indicates the expected return code. If the return code does not match the expected value, the configuration will return an error.
    + The default value is `(0, 1641, 3010)`.

+ **[bool] NoRestart** (Write): 
    + When this property as `$true`, This resource does not set `RebootNodeIfNeeded` to `$true` even if the system requires a reboot after installation.
    + The default value is `$false`.

+ **[string] PreAction** (Write): 
    + You can specify the PowerShell commands that will execute before installation or uninstallation.

+ **[string] PostAction** (Write): 
    + You can specify the PowerShell commands that will execute after installation or uninstallation.

+ **[string] PreCopyFrom** (Write): 
    + You can copy extra files before installation or uninstallation.
    + Copied files will delete automatically after installation finished.

+ **[string] PreCopyTo** (Write): 
    + The path of the directory which the file specified by `PreCopyTo` is saved.

----
## Examples
+ **Example 1**: Install Visual Studio Code [Simple scenario]
```Powershell
Configuration Example1
{
    Import-DscResource -ModuleName DSCR_Application
    cApplication VSCode
    {
        Name = 'Microsoft Visual Studio Code'
        InstallerPath = 'C:\VSCodeSetup-1.12.2.exe'
        Arguments = '/verysilent /mergeTasks="!runCode"'
    }
}
```

+ **Example 2**: Install Latest version of Flash Player Plugin [Advanced scenario]
```Powershell
Configuration Example2
{
    Import-DscResource -ModuleName DSCR_Application
    cApplication FlashPlayer
    {
        Name = 'Adobe Flash Player \d+ NPAPI'   # You can use RegExp when Fuzzy=$true
        Fuzzy = $true
        # Download installer from internet.
        InstallerPath = "http://fpdownload.macromedia.com/pub/flashplayer/latest/help/install_flash_player.exe"
        Arguments = '-install'
    }
}
```

+ **Example 3**: Install FireFox v53.0.3 to the custom directory [Complex scenario]
```Powershell
Configuration Example3
{
    Import-DscResource -ModuleName DSCR_Application
    cApplication Firefox53
    {
        Name = 'Mozilla Firefox [\.\d]+ \(x64 en-US\)' # Use RegExp
        Fuzzy = $true
        Version = '53.0.3'
        InstallerPath = '\\FileServer\Installer\FireFox Setup 53.0.3.exe'
        Credential = $Cred  # Credential for FileServer
        Arguments = '/INI=C:\config.ini'
        PreAction = '"[Install]`r`nInstallDirectoryPath=`"C:\FireFox\`"" | Out-File C:\config.ini -Encoding Ascii'    # Create config.ini before installation
        PostAction = 'del C:\config.ini -Force' # Remove config.ini after installation
    }
}
```