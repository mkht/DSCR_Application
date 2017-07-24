$output = 'C:\MOF'

Configuration cApplication_Sample
{
    Import-DscResource -ModuleName DSCR_Application

    cApplication FlashPlayer
    {
        Name = 'Adobe Flash Player \d+ NPAPI'   # You can use RegExp when Fuzzy=$true
        Fuzzy = $true
        # Download installer from internet.
        InstallerPath = "http://fpdownload.macromedia.com/pub/flashplayer/latest/help/install_flash_player.exe"
        Arguments = '-install'
        NoRestart = $true
    }
}

cApplication_Sample -OutputPath $output -ErrorAction Stop
Start-DscConfiguration -Path $output -Verbose -Wait -Force
Remove-DscConfigurationDocument -Stage Current, Previous, Pending -Force