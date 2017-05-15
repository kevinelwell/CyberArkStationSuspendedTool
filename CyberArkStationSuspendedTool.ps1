
Set-StrictMode -Version Latest

# This utility requires PowerShell major version 4 or above
If ($PSVersionTable.PSVersion.Major -ilt 4)
{
      # Display error dialog popup
      $message = "ERROR: THIS SERVER IS RUNNING POWERSHELL VERSION " + $PSVersionTable.PSVersion.Major + ".`r`n`r`nTHIS UTILITY REQUIRES POWERSHELL VERSION 5 OR HIGHER.`r`n`r`nCLICK OK TO EXIT."
	  $caption = "ERROR"
	  $buttons = [System.Windows.Forms.MessageBoxButtons]::OK
	  $icon = [System.Windows.Forms.MessageBoxIcon]::Error
	  $msgbox0 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
      break
}


<#
  .SYNOPSIS
  
  .DESCRIPTION
    
  .NOTES  
  Author: Kevin Elwell <Elwell1@gmail.com>  
  Version: 1.0 - 2016/11/16 - Initial release
           1.1 - 2016/11/18 - New functionality
           1.2 - 2016/12/8  - Added PACLI functions
           1.3 - 2016/12/20 - Cleaned up code/comments, base64 images for buttons and form icon
           1.3.3 - 2016/12/22 - Disabled contextual menus and added version to display on form
           1.4.1 - 2017/2/8 - Fixed PACLI functions, added Help button that launches documentation
           1.5.0 - 2017/3/27 - Updated functionality to read vault.ini, logonfile.ini and stationsuspended.ini
  .TODO
  troubleshoot "not responding" issues - possibly use start-job, get-job, receive-job, stop-job, wait-job cmdlets
  manually test and document results
  finalize script
  create custom connector to be able to run this tool from the CyberArk PSM
 
#>

    #CyberArk Station Suspended Tool Version 
    $toolver = "1.5.0"

#----------------------------------------------
#region Application Functions
#----------------------------------------------

function OnApplicationLoad {
	#Note: This function runs before the form is created
	#Note: To get the script directory in the Packager use: Split-Path $hostinvocation.MyCommand.path
	#Important: Form controls cannot be accessed in this function


# Read sections/values of StationSuspendedTool.ini into variables to be used within this tool (Oliver Lipkau <oliver@lipkau.net>)
Function Get-IniContent {
    <#
    .Synopsis
        Gets the content of an INI file

    .Description
        Gets the content of an INI file and returns it as a hashtable

    .Notes
        Author		: Oliver Lipkau <oliver@lipkau.net>
		Source		: https://github.com/lipkau/PsIni
                      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
        Version		: 1.0.0 - 2010/03/12 - OL - Initial release
                      1.0.1 - 2014/12/11 - OL - Typo (Thx SLDR)
                                              Typo (Thx Dave Stiff)
                      1.0.2 - 2015/06/06 - OL - Improvment to switch (Thx Tallandtree)
                      1.0.3 - 2015/06/18 - OL - Migrate to semantic versioning (GitHub issue#4)
                      1.0.4 - 2015/06/18 - OL - Remove check for .ini extension (GitHub Issue#6)
                      1.1.0 - 2015/07/14 - CB - Improve round-tripping and be a bit more liberal (GitHub Pull #7)
                                           OL - Small Improvments and cleanup
                      1.1.1 - 2015/07/14 - CB - changed .outputs section to be OrderedDictionary
                      1.1.2 - 2016/08/18 - SS - Add some more verbose outputs as the ini is parsed,
                      				            allow non-existent paths for new ini handling,
                      				            test for variable existence using local scope,
                      				            added additional debug output.

        #Requires -Version 2.0

    .Inputs
        System.String

    .Outputs
        System.Collections.Specialized.OrderedDictionary

    .Parameter FilePath
        Specifies the path to the input file.

    .Parameter CommentChar
        Specify what characters should be describe a comment.
        Lines starting with the characters provided will be rendered as comments.
        Default: ";"

    .Parameter IgnoreComments
        Remove lines determined to be comments from the resulting dictionary.

    .Example
        $FileContent = Get-IniContent "C:\myinifile.ini"
        -----------
        Description
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent

    .Example
        $inifilepath | $FileContent = Get-IniContent
        -----------
        Description
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent

    .Example
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini"
        C:\PS>$FileContent["Section"]["Key"]
        -----------
        Description
        Returns the key "Key" of the section "Section" from the C:\settings.ini file

    .Link
        Out-IniFile
    #>

    [CmdletBinding()]
    [OutputType(
        [System.Collections.Specialized.OrderedDictionary]
    )]
    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$FilePath,
        [char[]]$CommentChar = @(";"),
        [switch]$IgnoreComments
    )

    Begin
    {
        Write-Debug "PsBoundParameters:"
        $PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Debug $_ }
        if ($PSBoundParameters['Debug']) { $DebugPreference = 'Continue' }
        Write-Debug "DebugPreference: $DebugPreference"

        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"

        $commentRegex = "^([$($CommentChar -join '')].*)$"
        Write-Debug ("commentRegex is {0}." -f $commentRegex)
    }

    Process
    {
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"

        $ini = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)

        if (!(Test-Path $Filepath))
        {
            Write-Verbose ("Warning: `"{0}`" was not found." -f $Filepath)
            return $ini
        }

        $commentCount = 0
        switch -regex -file $FilePath
        {
            "^\s*\[(.+)\]\s*$" # Section
            {
                $section = $matches[1]
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding section : $section"
                $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                $CommentCount = 0
                continue
            }
            $commentRegex # Comment
            {
                if (!$IgnoreComments)
                {
                    if (!(test-path "variable:local:section"))
                    {
                        $section = $script:NoSection
                        $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                    }
                    $value = $matches[1]
                    $CommentCount++
                    Write-Debug ("Incremented CommentCount is now {0}." -f $CommentCount)
                    $name = "Comment" + $CommentCount
                    Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding $name with value: $value"
                    $ini[$section][$name] = $value
                }
                else { Write-Debug ("Ignoring comment {0}." -f $matches[1]) }

                continue
            }
            "(.+?)\s*=\s*(.*)" # Key
            {
                if (!(test-path "variable:local:section"))
                {
                    $section = $script:NoSection
                    $ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
                }
                $name,$value = $matches[1..2]
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding key $name with value: $value"
                $ini[$section][$name] = $value
                continue
            }
        }
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"
        Return $ini
    }

    End
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"}
}

# Name of the Section, in case the ini file had none
# Available in the scope of the script as `$script:NoSection`
$script:NoSection = "_"

# Get the directory this script is executing in
Function Get-ScriptDirectory {
    Return Split-Path -parent $PSCommandPath
}


# Function to check if an Active Directory Group exists
Function ADGroupExists {

   <#
  .SYNOPSIS
  Function that queries a Active Directory to check if an Active Directory Group exists
  .DESCRIPTION
  This function will use the parameter passed as the group name to query Active Directory to ssee if the group exists
  The function has a mandatory string parameter of an Active Directory user
  .EXAMPLE
  ADGroupExists 'ADGroup1'
  The above example will check to see if the Active Directory group ADGroup1 exists. 
  .PARAMETER string
  The string passed as a parameter to the function is the Active Directory group name to query
  .NOTES
  Author: Kevin Elwell <Elwell1@gmail.com>  
  Version: 1.0 - 2017/1/10 - Initial release
#>


[CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
        ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [string]$ADGroupName
    )
    $ADGroupexists = $(Try{Get-ADGroup -Identity $ADGroupName} Catch {$null})
    Return $ADGroupexists
}

    $UserName = $ENV:USERNAME 
    $Script:AuthorizedUserName = $UserName.ToUpper()

    $ComputerName = $ENV:ComputerName
    $Script:CompName = $ComputerName.ToUpper()
   
    # Get the directory this script is executing in into a global variable
    $Script:scriptPath = Get-ScriptDirectory
    
    # Define the paths to the StationSuspendedTool.ini, Vault.ini and logonfile.ini
    $Script:INIPath = "$scriptPath\PACLI\StationSuspendedTool.ini"
    $Script:VaultIni = "$scriptPath\PACLI\Vault.ini"
    $Script:logonIni = "$scriptPath\PACLI\logonfile.ini"
    $Script:PathtoPACLI = "$scriptPath\PACLI\pacli.exe"
    

               # Validate the $INIPath exists. If not, popup error message. Otherwise, retrieve contents of INI file
            If(!(Test-Path $INIPath)) {
            
            # Display error dialog popup
    	    $message = "ERROR: UNABLE TO VALIDATE ""$INIPath"".`r`n`r`nPLEASE CHECK THE INI FILE EXISTS AND THE FULL PATH TO THE INI IS PROVIDED."
		    $caption = "ERROR"
		    $buttons = [System.Windows.Forms.MessageBoxButtons]::OK
		    $icon = [System.Windows.Forms.MessageBoxIcon]::Error
		    $msgbox96 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
            Break

            }else{
            
            # Define the path to the StationSuspendedTool.ini and retrieve the contents
            $Script:FileContent = Get-IniContent $INIPath -ErrorAction SilentlyContinue #-Verbose
            }

            # Validate the $VaultIni exists. If not, popup error message. Otherwise, retrieve contents of INI file
            If(!(Test-Path $VaultIni)) {
            
            # Display error dialog popup
    	    $message = "ERROR: UNABLE TO VALIDATE ""$VaultIni"".`r`n`r`nPLEASE CHECK THE INI FILE EXISTS AND THE FULL PATH TO THE INI IS PROVIDED."
		    $caption = "ERROR"
		    $buttons = [System.Windows.Forms.MessageBoxButtons]::OK
		    $icon = [System.Windows.Forms.MessageBoxIcon]::Error
		    $msgbox97 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
            Break

            }else{
            
            # Retrieve contents of the Vault.ini
            $Script:VaultContent = Get-IniContent $VaultIni -ErrorAction SilentlyContinue #-Verbose
            }

            # Validate the $logonIniContent exists. If not, popup error message. Otherwise, retrieve contents of INI file
            If(!(Test-Path $logonIni)) {
            
            # Display error dialog popup
    	    $message = "ERROR: UNABLE TO VALIDATE ""$logonIni"".`r`n`r`nPLEASE CHECK THE INI FILE EXISTS AND THE FULL PATH TO THE INI IS PROVIDED."
		    $caption = "ERROR"
		    $buttons = [System.Windows.Forms.MessageBoxButtons]::OK
		    $icon = [System.Windows.Forms.MessageBoxIcon]::Error
		    $msgbox98 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
            Break

            }else{
            
            # Define the path to the logonfile.ini and retrieve the contents
            $Script:logonContent = Get-IniContent $logonIni -ErrorAction SilentlyContinue #-Verbose
            }

            # Validate the $PathtoPACLI exists. If not, popup error message. 
            If(!(Test-Path $PathtoPACLI)) {
            
            # Display error dialog popup
    	    $message = "ERROR: UNABLE TO VALIDATE ""$PathtoPACLI"".`r`n`r`nPLEASE CHECK THE EXE FILE EXISTS AND THE FULL PATH TO THE EXE IS PROVIDED."
		    $caption = "ERROR"
		    $buttons = [System.Windows.Forms.MessageBoxButtons]::OK
		    $icon = [System.Windows.Forms.MessageBoxIcon]::Error
		    $msgbox99 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
            Break

            }

   
   # Define the Active Directory Support Group that grants permissions to run this utility from the StationSuspended.ini file
   $CASupportGroup = $FileContent["ActiveDirectory"]["CyberArkADSupportGroup"]
   

   # Initialize some variables to $false
   [boolean]$inADGroup = $false    
   $Groupexists = $(Try{Get-ADGroup -Identity $CASupportGroup} Catch {$null})
    
    If($Groupexists = ADGroupExists $CASupportGroup){

    If($ADUser = Get-ADUser -filter {sAMACCOUNTName -eq $AuthorizedUserName} -properties givenName, Surname, samAccountName, Enabled | Select givenName, Surname, SamAccountName, Enabled -ErrorAction Stop) {
    
    # If the user object exists in Active Directory, check to see if its a member of the $CASupportGroup Active Directory group 
    $CASupportGroupMembers = Get-ADGroupMember -Identity $CASupportGroup -Recursive | Select -ExpandProperty samAccountName -ErrorAction Stop

    
        # Based on checking Active Directory group membership, assign true/false to $inADGroup variable for use later in script
        if ($CASupportGroupMembers -eq $AuthorizedUserName) { 

        return $true #return true for success or false for failure

            }
        }
    }
}

function OnApplicationExit {
	#Note: This function runs after the form is closed
	#TODO: Add custom code to clean up and unload snapins when the application exits
	
	$script:ExitCode = 0 #Set the exit code
}

function quitscript {
    $form1.Close()
    [System.Windows.Forms.Application]::exit($null)
}

    
#endregion    


Function GenerateForm {


	#----------------------------------------------
	#region Import Assemblies
	#----------------------------------------------
	[void][reflection.assembly]::Load("System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	[void][reflection.assembly]::Load("System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
	[void][reflection.assembly]::Load("mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	[void][reflection.assembly]::Load("System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
	#endregion Import Assemblies

	#----------------------------------------------
	#region Generated Form Objects
	#----------------------------------------------
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$form1 = New-Object System.Windows.Forms.Form
    $ToolVersion = New-Object System.Windows.Forms.Label
	$ADConnStatus = New-Object System.Windows.Forms.Label
    $VaultStatus = New-Object System.Windows.Forms.Label
    $PSMStatus = New-Object System.Windows.Forms.Label
    $InputBoxLabel = New-Object System.Windows.Forms.Label
    $InputBox = New-Object System.Windows.Forms.TextBox
    $outputBoxLabel = New-Object System.Windows.Forms.Label
    $outputBox = New-Object System.Windows.Forms.TextBox
    $outputBox1 = New-Object System.Windows.Forms.TextBox
    $outputBox3 = New-Object System.Windows.Forms.TextBox
    $outputBox4 = New-Object System.Windows.Forms.TextBox
    $outputBoxLabel1 = New-Object System.Windows.Forms.Label
    $outputBoxLabel2 = New-Object System.Windows.Forms.Label
    $outputBoxLabel3 = New-Object System.Windows.Forms.Label
    $outputBoxLabel4 = New-Object System.Windows.Forms.Label   
    $pictureBox = New-Object Windows.Forms.PictureBox
    $ButtonSearch = New-Object System.Windows.Forms.Button
    $ButtonActivate = New-Object System.Windows.Forms.Button
    $ButtonReset = New-Object System.Windows.Forms.Button
    $ButtonExit = New-Object System.Windows.Forms.Button
    $ButtonHelpYou = New-Object System.Windows.Forms.Button
    $tooltip1 = New-Object System.Windows.Forms.ToolTip
    $ButtonHelp = New-Object System.Windows.Forms.Button
    $tooltip1.IsBalloon = $true
    $contextMenuStrip = New-Object System.Windows.Forms.ContextMenuStrip
    $menuItem1 = New-Object System.Windows.Forms.ToolStripMenuItem

    #endregion Generated Form Objects

	#----------------------------------------------
	# User Generated Script
	#----------------------------------------------



############################################## Start functions


#region FormEvent_Load
# ONLY DO PING-HOST, CHECK-ADMODULE, GET-INICONTENT, GET-CURRIP WITHIN $FormEvent_Load={} AND DISPLAY LABELS LOGIC
$FormEvent_Load={
        
    #region Disable contextual menus for all textboxes
    $InputBox.ContextMenuStrip = $contextMenuStrip
    $outputBox.ContextMenuStrip = $contextMenuStrip
    $outputBox1.ContextMenuStrip = $contextMenuStrip
    $outputBox3.ContextMenuStrip = $contextMenuStrip
    $outputBox4.ContextMenuStrip = $contextMenuStrip
    $contextMenuStrip.Visible = $false
    #endregion Disable contextual menu for all textboxes

    # Initialize the $ButtonSearch.Enabled Variable to $false so when the form initially loads, the button is not enabled until
    # the user enters something into the textbox
    $ButtonSearch.Enabled = $false



# Get the IP address this script is being executed on and compare to the IP address in the .ini file
Function Get-CurrIP {
    $ThisIP = Get-CIMInstance Win32_networkAdapterconfiguration -filter "ipenabled = 'True'" | Select IPAddress
    [string]$CurrIP = $ThisIP.ipaddress[0]

        Return $CurrIP
}


# Check if the Active Directory PowerShell module exists
Function Check-ADModule {

<#
  .SYNOPSIS
  This function will check if a PowerShell module exists (PowerShell module name is passed as a parameter to the function)
  .DESCRIPTION
  This function will use the parameter passed as the name of the PowerShell module to check to see if it exists
  The function has a mandator parameter of a string that you want written to the log file.
  .EXAMPLE
  CheckADModule "ActiveDirectory"
  The above example will check to see if the ActiveDirectory PowerShell module is present
  .PARAMETER string
  The string passed as a parameter to the function is the PowerShell module name you want to check if it exists
  .NOTES  
  Author: Kevin Elwell <Elwell1@gmail.com>  
  Version: 1.0 - 2016/11/12 - Initial release
  .NOTE This has only been tested/validated wo work when the PowerShell Module is in the C:\Windows\System32\WindowsPowerShell\v1.0\Modules or C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules directories.
#>

[CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
       # [Alias("ADModule")] 
        [string]$ADModule
    )
    
    # Initialize $ModuleExists variable to false
    $ModuleExists = $false
    
    # Get list of available PowerShell modules to see if the Active Directory module is present
    $ADModuleExists = Get-Module -ListAvailable -Name $ADModule -ErrorAction SilentlyContinue
    [bool]$ModuleExists = Test-Path $ADModuleExists.Path -ErrorAction SilentlyContinue

    $output =@()
    $output += $ModuleExists

    Return $output
    
    }

# Function to ping a remote machine
Function Ping-Host {
    
    param (
        [parameter(Mandatory=$true)]
        [string]$host2ping
          )
          # Initialize $Online variable to $false
          $Online = $false

          # Ping the host name/IP passed as a parameter
          [bool]$Online = Test-Connection -Computername $host2ping -Quiet -Count 2

    #Return the bool result of the ping
    Return $Online
}



#region ADModuleCheck
    # Execute the CheckADModule function and pipe output into $connStatus variable
    $connStatus = Check-ADModule "ActiveDirectory" -ErrorAction SilentlyContinue

    # Display results of Check-ADModule function to user and disable search button if Active Directory PowerShell module is missing
    If($connStatus) {
        $ADConnStatus.BackColor = [Drawing.Color]::Green
		$ADConnStatus.ForeColor = [Drawing.Color]::White
        $ADConnStatus.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
		$ADConnStatus.Text = "ACTIVE DIRECTORY MODULE PRESENT"

    # Import Active Directory PowerShell module
    Try {
        Import-Module ActiveDirectory -ErrorAction Stop >$null
        }
    Catch
        {
        Write-Host $_
        Break
        }
    }
    
    If(!($connStatus)) {	    
    	$ADConnStatus.BackColor = [Drawing.Color]::Red
		$ADConnStatus.ForeColor = [Drawing.Color]::Black
        $ADConnStatus.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
		$ADConnStatus.Text = "ERROR: ACTIVE DIRECTORY MODULE MISSING"
        $tooltip1.SetToolTip($ADConnStatus, "THIS UTILITY REQUIRES THE MICROSOFT ACTIVE DIRECTORY POWERSHELL CMDLETS.")
        $ButtonSearch.Enabled = $false        
        $InputBoxLabel.Visible = $false
        $InputBox.Visible = $false
    }
#endregion

#region Ping CyberArk vault IP address
    
    # Define Vault IP address from Vault.ini file
    [string]$VaultIP = $VaultContent["_"]["Address"]

    # Ping Vault IP address to make sure its up and running
    $vaultUp = Ping-Host $vaultIP
    
    # Display results of Ping-Host function to user and disable search button if vault not online
    If($VaultUp){ 
        $VaultStatus.BackColor = [Drawing.Color]::Green
	    $VaultStatus.ForeColor = [Drawing.Color]::White
        $VaultStatus.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
	    $VaultStatus.Text = "CYBERARK VAULT IS ONLINE"
    }
    If(!($VaultUp)){
        $VaultStatus.BackColor = [Drawing.Color]::Red
	    $VaultStatus.ForeColor = [Drawing.Color]::Black
        $VaultStatus.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
	    $VaultStatus.Text = "CYBERARK VAULT IS OFFLINE"
        $tooltip1.SetToolTip($VaultStatus, "UNABLE TO COMMUNICATE WITH THE CYBERARK VAULT. PLEASE CONTACT IT SECURITY.")
        $ButtonSearch.Enabled = $false
        $InputBoxLabel.Visible = $false
        $InputBox.Visible = $false
    }
#endregion

#region Check if this script is running from the PSM
    # Compare the PSM IP address from the StationSuspendedTool.ini to the IP address this script is running on
    $MyIP = Get-CurrIP

    # Define PSM IP from StationSuspendedTool.ini file
    $PSMIP = $FileContent["CyberArk"]["PSMIP"]

    # Display results of comparing IP addresses to user and disable search button if the IP addresses are not the same
    If ($MyIP -eq $PSMIP) {
        $PSMStatus.BackColor = [Drawing.Color]::Green
	    $PSMStatus.ForeColor = [Drawing.Color]::White
        $PSMStatus.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
        #$PSMStatus.Text = "RUNNING FROM PSM"
	    $PSMStatus.Text = "RUNNING FROM SERVER"
    }

    If ($MyIP -ne $PSMIP) {
        $PSMStatus.BackColor = [Drawing.Color]::Red
	    $PSMStatus.ForeColor = [Drawing.Color]::Black
        $PSMStatus.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
        
        #####################################################################################################################################
        # Use code below for running from a secure server
        $PSMStatus.Text = "NOT RUNNING FROM SERVER"
        $tooltip1.SetToolTip($PSMStatus, "THIS UTILITY MUST BE EXECUTED FROM A SECURE SERVER.")
        #####################################################################################################################################
        
        #####################################################################################################################################
        # Use code below for running from custom connector on PSM
        #$PSMStatus.Text = "NOT RUNNING FROM PSM"
        #$tooltip1.SetToolTip($PSMStatus, "THIS UTILITY MUST BE EXECUTED FROM THE PRIVILEGED SESSION MANAGER.")       
        #####################################################################################################################################
        $ButtonSearch.Enabled = $false
        $InputBoxLabel.Visible = $false
        $InputBox.Visible = $false
    }

#endregion

}
#endregion FormEvent_Load

#region Form_StateCorrection_Load
$Form_StateCorrection_Load=
	{
		#Correct the initial state of the form to prevent the .Net maximized form issue
		$form1.WindowState = $InitialFormWindowState
	}

#endregion Form_StateCorrection_Load


#region Get-UserInfo Function
# Function to check if the user ID entered is in the Active Directory group that provides access into CyberArk
Function Get-UserInfo {
   
   <#
  .SYNOPSIS
  Function that queries a Active Directory user object to retrieve attributes
  .DESCRIPTION
  This function will use the parameter passed as the user name to query Active Directory and retrieve several user object attributes
  The function has a mandatory string parameter of an Active Directory user
  .EXAMPLE
  Get-UserInfo 'john'
  The above example will check to see if the user exists in Active Directory. If the user exists, query the user object
  to get the givenName, surName, samAccountName, if the account is enabled and is a member of the Active Directory group that is 
  contained within the StationSuspendedTool.ini
  .EXAMPLE
  $allusersoutput, $userfound, $grpmember, $fail = Get-UserInfo 'john'
  .PARAMETER string
  The string passed as a parameter to the function is the Active Directory user name to query
  .NOTES
  Author: Kevin Elwell <Elwell1@gmail.com>  
  Version: 1.0 - 2016/12/6 - Initial release
  Version: 1.3 - 2016/12/9 - Added input validation and message boxes
#>

[CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
        ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [string]$ADUserNAme
    )

#region Super Secret Admin
    # By providing a special alphanumeric character prefix, we enable a hidden button that will run the DEACTIVATETRUSTEDNETWORKAREA function 
    # and then the ACTIVATETRUSTEDNETWORKAREA function. IMPORTANT: the prefix defined in the StationSuspendedTool.ini MUST BE NUMBERS OR CAPITAL LETTERS
    # Get CyberArk Active Directory group from the StationSuspendedTool.ini and check if the user name passed to the function is a member of the group
    $SSAPrefix = $FileContent["AdminFunctions"]["SuperSecretAdminPrefix"]
 
    # Initialize $IsSecretAdmin to $False
    $IsSecretAdmin = $False   

    # Check to see if $ADUserNAme starts with the super secret characters
    $SuperSecretAdmin = $ADUserNAme.StartsWith("$SSAPrefix")
    If($SuperSecretAdmin) {

        # Set $IsSecretAdmin to $True
        $IsSecretAdmin = $True
        
        # Since the user entered is a super secret admin, trim off $SSAPrefix from $ADUserNAme 
        $ADUserNAme = $ADUserNAme.TrimStart("$SSAPrefix")
    }

#endregion Super Secret Admin
    
    # Validate the $ADUserNAme does not contail illegal characters
    If($ADUserNAme -cnotmatch "^[a-zA-Z0-9]*$") {

        # Display error dialog popup
        $message = "ERROR: THE USERNAME YOU ENTERED ""$ADUserNAme""CONTAINS NON-ALPHANUMERIC CHARACTERS AND/OR SPACES.`r`n`r`nPLEASE TRY AGAIN."
		$caption = "ERROR"
		$buttons = [System.Windows.Forms.MessageBoxButtons]::OK
		$icon = [System.Windows.Forms.MessageBoxIcon]::Error
		$msgbox1 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)

    }

    # Get CyberArk Active Directory group from the StationSuspendedTool.ini and check if the user name passed to the function is a member of the group
    $CAADUserGroup = $FileContent["ActiveDirectory"]["CyberArkADUserGroup"]

    # Initialize some variables to $false
    [boolean]$returnValue = $false
    [boolean]$failed = $false
    [boolean]$found = $false

    # Create array for the results to be stored in
    $output = @()
    
# Query Active Directory user object attributes "givenName, Surname, SamAccountName and Enabled" for the user object passed to the function
Try {
    
    If($allusers = Get-ADUser -filter {sAMACCOUNTName -eq $ADUserNAme} -properties givenName, Surname, samAccountName, Enabled | Select givenName, Surname, SamAccountName, Enabled -ErrorAction Stop) {
        
    # Add results to the array
    $output += $allusers

        # User object exists in Active Directory, proceed to checking user object group membership
        # Set variable $found to $true
        [boolean]$found = $true
    

    # If the user object exists in Active Directory, check to see if its a member of the CyberArk Active Directory group 
    $CAADGroupMembers = Get-ADGroupMember -Identity $CAADUserGroup -Recursive | Select -ExpandProperty samAccountName -ErrorAction Stop

    
        # Based on checking Active Directory group membership, assign true/false to $returnVal variable for use later in script
        if ($CAADGroupMembers -eq $ADUserNAme) { 
            
            # Set variable $returnValue to $true
            [boolean]$returnValue = $true
        }else{
             # If $returnValue = $false, the user exists in Active Directory but is not in the $CAADUserGroup. Display error message to user.
             If($returnValue -eq $false) {
            
            # Display error dialog popup
    	    $message = "ERROR: ""$ADUserNAme"" WAS FOUND IN ACTIVE DIRECTORY.`r`n`r`nHOWEVER, THE USER IS NOT IN THE ""$CAADUserGroup"" ACTIVE DIRECTORY GROUP."
		    $caption = "ERROR"
		    $buttons = [System.Windows.Forms.MessageBoxButtons]::OK
		    $icon = [System.Windows.Forms.MessageBoxIcon]::Error
		    $msgbox2 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
    
            }
        }

    }else{

    # User object does NOT exist in Active Directory   
        # Set variable $allusers to $false
        [boolean]$allusers = $false
        
        # User object does NOT exist in Active Directory
        If($allusers -eq $false) {
        
        # Display error dialog popup
    	$message = "ERROR: ""$ADUserNAme"" WAS NOT FOUND IN ACTIVE DIRECTORY."
		$caption = "ERROR"
		$buttons = [System.Windows.Forms.MessageBoxButtons]::OK
		$icon = [System.Windows.Forms.MessageBoxIcon]::Error
		$msgbox3 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
    
        }   
    }

}

# Catch errors here
Catch {
    Write-host $_.Exception.Message
    [boolean]$failed = $true

      }

    Return $output, $found, $returnValue, $failed, $IsSecretAdmin
}
#endregion Get-UserInfo Function


#region PACLI Functions
Function PACLIinit {

    # Initialize the $ex Variable to a null value
    $ex = ""

    # Initialize the PACLI
    & $PathtoPACLI INIT    

    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex

}


Function PACLIparamfile {

    # Initialize the $ex Variable to a null value
    $ex = ""
    
    # Define parameters from various ini files
    [string]$VaultName = $VaultContent["_"]["Vault"]
    # Trim off the leading/trailing space if present
    [string]$VaultName = $VaultName.Trim()
    # Trim off the double quotes if present
    [string]$VaultName = $VaultName.Replace('"',"")
    
    # Define param file
    & $PathtoPACLI DEFINEFROMFILE VAULT=`"$VaultName`" PARMFILE=`"$VaultIni`"
    
    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex

}


Function PACLIlogon {

    # Initialize the $ex Variable to a null value
    $ex = ""
    
    # Define parameters from various ini files
    [string]$VaultName = $VaultContent["_"]["Vault"]
    # Trim off the leading/trailing space if present
    [string]$VaultName = $VaultName.Trim()
    # Trim off the double quotes if present
    [string]$VaultName = $VaultName.Replace('"',"")
    [string]$LogonUser = $logonContent["_"]["Username"]

    #PACLI logon
    & $PathtoPACLI LOGON VAULT=`"$VaultName`" USER=`"$LogonUser`" LOGONFILE=`"$logonIni`"    

    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex

}


Function PACLIuserinfo {

    # Initialize the $ex Variable to a null value
    $ex = ""
    
    # Define parameters from various ini files
    [string]$VaultName = $VaultContent["_"]["Vault"]
    # Trim off the leading/trailing space if present
    [string]$VaultName = $VaultName.Trim()
    # Trim off the double quotes if present
    [string]$VaultName = $VaultName.Replace('"',"")
    [string]$LogonUser = $logonContent["_"]["Username"]

    # PACLI get user info
    $PACLICheckLockedOut = & $PathtoPACLI TRUSTEDNETWORKAREASLIST VAULT=`"$VaultName`" USER=`"$LogonUser`" TRUSTERNAME=`"$networkID`" --% OUTPUT(NAME,ACTIVE,VIOLATIONCOUNT)
    
    # Split results of get user info into 3 variables
    $option = [System.StringSplitOptions]::RemoveEmptyEntries
    $trustedNetworkName, $UserActive, $failCount = $PACLICheckLockedOut.Split(' ',3, $option)
        
        # Station suspended ($UserActive -eq "YES")
        If($UserActive -eq "YES"-and $failCount -ne 5){
        $UserActive = "FALSE"
        }
    
        # Station suspended due to 5 or more failed login attempts ($UserActive -eq "YES" and $failCount -eq 5)
        If($UserActive -eq "YES" -and $failCount -eq 5){
            $UserActive = "TRUE"
        }

        # Station NOT suspended ($UserActive -eq "NO")
        If($UserActive -eq "NO"){
            $UserActive = "TRUE"
        }
    
    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex, $trustedNetworkName, $UserActive, $failCount

}


Function PACLIactivateuser {

    # Initialize the $ex Variable to a null value
    $ex = ""

    # Define parameters from various ini files
    [string]$VaultName = $VaultContent["_"]["Vault"]
    # Trim off the leading/trailing space if present
    [string]$VaultName = $VaultName.Trim()
    # Trim off the double quotes if present
    [string]$VaultName = $VaultName.Replace('"',"")
    [string]$LogonUser = $logonContent["_"]["Username"]
    [string]$networkArea = $FileContent["CyberArk"]["NetworkArea"]

    # Activate user
    & $PathtoPACLI ACTIVATETRUSTEDNETWORKAREA VAULT=`"$VaultName`" USER=`"$LogonUser`" TRUSTERNAME=`"$networkID`" NETWORKAREA=`"$networkArea`"
    
    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex

}


Function PACLIdeactivateuser {

    # Initialize the $ex Variable to a null value
    $ex = ""

    # Define parameters from various ini files
    [string]$VaultName = $VaultContent["_"]["Vault"]
    # Trim off the leading/trailing space if present
    [string]$VaultName = $VaultName.Trim()
    # Trim off the double quotes if present
    [string]$VaultName = $VaultName.Replace('"',"")
    [string]$LogonUser = $logonContent["_"]["Username"]
    [string]$networkArea = $FileContent["CyberArk"]["NetworkArea"]

    # Deactivate user
    & $PathtoPACLI DEACTIVATETRUSTEDNETWORKAREA VAULT=`"$VaultName`" USER=`"$LogonUser`" TRUSTERNAME=`"$networkID`" NETWORKAREA=`"$networkArea`"

    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex

}


Function PACLIlogoff {

    # Initialize the $ex Variable to a null value
    $ex = ""
    
    # Define parameters from various ini files
    [string]$VaultName = $VaultContent["_"]["Vault"]
    # Trim off the leading/trailing space if present
    [string]$VaultName = $VaultName.Trim()
    # Trim off the double quotes if present
    [string]$VaultName = $VaultName.Replace('"',"")
    [string]$LogonUser = $logonContent["_"]["Username"]
    

    #PACLI logoff
    & $PathtoPACLI LOGOFF VAULT=`"$VaultName`" USER=`"$LogonUser`"    

    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex

}


Function PACLIterm {

    # Initialize the $ex Variable to a null value
    $ex = ""

     # PACLI TERM
    & $PathtoPACLI TERM

    # Capture the exit code
    $ex = $LASTEXITCODE
    Return $ex
    
}
#endregion PACLI Functions

#region handler_btnSearch_Click
$handler_btnSearch_Click={

    # Get the username entered
    #$UserName = $InputBox.Text
    $Script:UserName = $InputBox.Text
    [boolean]$enabled = "False"
    
    #Clear the inputbox text after clicking the Search button
    $InputBox.Clear()
    $outputBox.Clear()
    $outputBox1.Clear()
    $outputBox3.Clear()
    $outputBox4.Clear()
    $outputBox.Refresh()
    $outputBox1.Refresh()
    $outputBox3.Refresh()
    $outputBox4.Refresh()
    $form1.controls.Remove($pictureBox)

    # Disable Search button after a search
    $ButtonSearch.Enabled = $false

    # Execute the Get-UserInfo function and get the results into several variables
    $allusersoutput, $userfound, $grpmember, $fail, $IsSSA = Get-UserInfo $UserName

################ code broken here ################    
# need to NOT execute the PACLI functions if the user is NOT in the correct AD group
     
        # Assign specific Active Directory attributes to variables
        $Script:firstName = $allusersoutput.givenName
        $Script:lastName = $allusersoutput.SurName
        $Script:UserNameEnabled = $allusersoutput.Enabled
        $Script:networkID = $allusersoutput.samAccountName

    # If the user is in the AD group, check user status within CyberArk.
    If($grpmember){

    # Execute the PACLIinit, PACLIparamfile, PACLIlogon, PACLIuserinfo functions. NOTE: PACLIlogoff and PACLIterm functions will only be executed if the $PACLIuseractive variable is FALSE
    $Init = PACLIinit
    $ParamFile = PACLIparamfile
    $logon = PACLIlogon
    $PACLIuserinfoExitCode, $PACLInetworkname, $PACLIuseractive, $PACLIfailcount = PACLIuserinfo

################################
    $logoff = PACLIlogoff
    $term = PACLIterm
################################
        # Enable the outputBoxes and populate them with the specific attributes 
        $outputBox.Text = "$firstName $lastName"
        $outputBox1.Text = $networkID

        # Enable outputBox3 and outputBox4 and populate them with the specific attributes 
        $outputBox3.Text = $PACLIuseractive
        $outputBox4.Text = $PACLIfailcount
    
    # Verify if the username entered is enabled within Active Directory and assign an image based on result
    If($UserNameEnabled-eq $True) {
        $file = (get-item $scriptPath\Resources\greenshield.png)
        $img = [System.Drawing.Image]::Fromfile($file)
    }
    Elseif($UserNameEnabled -eq $false) {
        $file = (get-item $scriptPath\Resources\RedCircle.png)
        $img = [System.Drawing.Image]::Fromfile($file)
    }else{
        # Do not assign an image for $file variable
    }

    # If the $PACLIuseractive is TRUE, the user cannot login to CyberArk. Therefore display the $ButtonActivate button
    If($PACLIuseractive -eq "TRUE"){
        $form1.Controls.Add($ButtonActivate)
    }
}    

#region pictureBox
    ############################################### Start pictureBox
    $pictureBox.Location = New-Object System.Drawing.Size(360,130)
    $pictureBox.Size = New-Object System.Drawing.Size(150,20)
    $pictureBox.Visible = $True
    $pictureBox.Width =  $img.Width
    $pictureBox.Height =  $img.Size.Height
    $pictureBox.Image = $img
    $form1.controls.add($pictureBox)
    ############################################### End pictureBox 
#endregion pictureBox


#region ButtonReset Controls
    ############################################### Start ButtonReset Controls
    # Since the user entered the Super Secret Admin prefix, display the Super Secret Admin button
    If($IsSSA){
        $form1.Controls.Add($ButtonReset)
    }
    ############################################### End ButtonReset Controls
#endregion ButtonReset Controls


}
#endregion handler_btnSearch_Click

#region handler_btnCancel_Click
$handler_btnCancel_Click={
        $form1.Close()   
}
#endregion handler_btnCancel_Click

#region handler_btnActivate_Click
$handler_btnActivate_Click={

# Login to CyberArk and execute the PACLIinit, PACLIparamfile, PACLIlogon, PACLIactivateuser, PACLIuserinfo, PACLIlogoff and PACLIterm functions 
    $Init = PACLIinit
    $ParamFile = PACLIparamfile
    $logon = PACLIlogon
    $activate = PACLIactivateuser
    $PACLIuserinfoExitCode, $PACLInetworkname, $PACLIuseractive, $PACLIfailcount = PACLIuserinfo

        # Populate outputBox3 and outputBox4 with the specific attributes and refresh them 
        $outputBox3.Text = $PACLIuseractive
        $outputBox4.Text = $PACLIfailcount
        $outputBox3.Refresh()
        $outputBox4.Refresh()
    
    $logoff = PACLIlogoff
    $term = PACLIterm
    
    # Remove activate button after activating a user
    $form1.Controls.Remove($ButtonActivate)
    
}
#endregion handler_btnActivate_Click


#region handler_btnReset_Click
$handler_btnReset_Click={
    
    # Disable Reset button after clicking it
    $ButtonReset.Enabled = $false
    
    # Execute the PACLIinit, PACLIparamfile, PACLIlogon, PACLIuserinfo, PACLIlogoff and PACLIterm functions
    $Init = PACLIinit
    $ParamFile = PACLIparamfile
    $logon = PACLIlogon
    $PACLIuserinfoExitCode, $PACLInetworkname, $PACLIuseractive, $PACLIfailcount = PACLIuserinfo
    $deactivate = PACLIdeactivateuser

    # Update outputBox3 and outputBox4 with the specific attributes and refresh them
    $PACLIuserinfoExitCode, $PACLInetworkname, $PACLIuseractive, $PACLIfailcount = PACLIuserinfo
        
        # Populate outputBox3 and outputBox4 with the specific attributes and refresh them
        $outputBox3.Text = $PACLIuseractive
        $outputBox4.Text = $PACLIfailcount
        $outputBox3.Refresh()
        $outputBox4.Refresh()

    $activate = PACLIactivateuser
    $PACLIuserinfoExitCode, $PACLInetworkname, $PACLIuseractive, $PACLIfailcount = PACLIuserinfo
    
        # Populate outputBox3 and outputBox4 with the specific attributes and refresh them
        $outputBox3.Text = $PACLIuseractive
        $outputBox4.Text = $PACLIfailcount
        $outputBox3.Refresh()
        $outputBox4.Refresh()

    $logoff = PACLIlogoff
    $term = PACLIterm

    # Remove the reset button from the form
    $form1.Controls.Remove($ButtonReset)

}
#endregion handler_btnReset_Click


#region handler_btnHelpYou_Click # EASTER EGG
$handler_btnHelpYou_Click={
    $base64wav = "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awBwAHAAcgB7AIEAggCKAIgAkwCJAJEAfwCKAHwAfQB1AHMAcwBmAHMAZwB3AFsAbgBeAG8AUABfAEQATQAzADwAIAAiAAsAEAD///3/8f/u/+r/3f/j/9T/3//N/9//zv/h/9P/6//a/+7/6P///+7/AQD2/wQA9P8HAPn/AgDy//7/+f/+//D/+f/1//z/6//0/+L/7v/U/97/wP/S/7H/wP+k/7r/nP+z/6D/uP+c/7f/nv+5/5j/r/+L/6X/g/+P/2//ff9j/23/Vv9a/03/UP9C/0X/O/84/zL/Mv8q/yj/KP8i/yT/IP8t/yP/L/8k/zn/K/9A/yj/Pv8s/0X/Iv8+/yX/P/8a/zr/Hv8y/xr/Jv8a/xf/Ff8G/xH/+f4K/+7+Dv/x/hL//P4o/xL/OP8u/1f/RP9o/1v/eP9p/4b/bv+B/3X/iv93/4L/gP+K/4f/kP+V/5v/nv+m/6v/sf+0/7f/tP+//7n/vP+x/77/rv+3/6P/sf+Y/6n/jf+f/4L/oP99/5r/eP+m/37/qf+B/7b/if/C/5b/yv+e/9f/tf/e/7//8f/a//z/7v8SAAwAIgAhADYAPgBFAE0AUwBkAF0AcABmAIIAdQCJAH0AlQCJAJMAigCTAI4AiQCHAIEAgQBzAHkAcQB2AGkAeQBtAH4AcQCLAHUAkgB/AJsAhQChAIoApQCUAKUAkACoAJwAogCUAKIAlQCXAJIAmACOAI0AkQCOAJQAjwCbAJQApgCcAK4AoACxAKQAtACcAK8AmwCsAI4ArQCLAKUAhgCsAIUAoACGAKEAhgCTAIIAigCCAHwAegB1AHsAcAB6AG8AewBwAH0AcgB8AHAAdQBwAHUAbgBkAGsAZwBvAF8AawBgAG0AYQBpAFgAYwBVAF4ARwBVAD8AWgA9AF8APgBuAEkAfQBYAIgAYQCMAGkAhwBnAH8AYQBvAFkAaQBXAGkAWwBrAGYAeQB1AH0AfgCEAIYAhgCGAIIAgwCEAIIAhACEAI0AjQCUAJwAmwCkAJwArgCaAKoAkwCnAI4AngCMAJwAlQCdAKIAqAC5ALsAygDGANoA2ADiANUA5ADWAN0AzQDbAMIAzAC3AMYApwC2AJsApwCHAJEAdAB+AF4AYgBGAFcANABAACUAPQAbACwAFAApAAoAEwAAAAcA7v/r/9v/0//F/7v/r/+h/5n/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"

    $wav = [System.Convert]::FromBase64String($base64wav)
    Set-Content -Path "$env:temp\1yx48.wav" -Value $wav -Encoding Byte

    # play the file once
    $wavsound = New-Object System.Media.SoundPlayer
    $wavsound.SoundLocation = "$env:temp\1yx48.wav"
    $wavsound.Play()
    Start-Sleep -s 2
    $wavsound.Stop() 
    
Remove-Item -Path "$env:temp\1yx48.wav" -Force

}

#endregion handler_btnHelpYou_Click # EASTER EGG

#region handler_btnHelp_Click
$handler_btnHelp_Click={

    # Define path to the documentation file
    $helpurl = "$scriptPath\Resources\Documentation.html"
    
    $ie3 = New-Object -COMObject "InternetExplorer.Application"
    $ie3.visible = $true
    $ie3.menubar = $false
    $ie3.height = 1000
    $ie3.width = 1000
    $ie3.resizable = $true
    $ie3.addressbar = $false
    $ie3.toolbar = $false
    
    # Open the documentation within Internet Explorer
    $ie3.navigate($helpurl)    
}
#endregion handler_btnHelp_Click

    ############################################## Start Inputbox and Inputboxlabel
    $InputBoxLabel.Location = New-Object System.Drawing.Size(15,25)
    $InputBoxLabel.Size = New-Object System.Drawing.Size(450,20)
    $InputBoxLabel.Text = "PLEASE ENTER THE USER ACCOUNT TO CHECK"
    $form1.Controls.Add($InputBoxLabel)

    $InputBox.Name ="userID"
    $InputBox.BorderStyle = 'Fixed3D'
    $InputBox.Location = New-Object System.Drawing.Size(20,50) 
    $InputBox.Size = New-Object System.Drawing.Size(150,20)
    $tooltip1.SetToolTip($InputBox, "ENTER THE USER ACCOUNT TO CHECK WITHIN CYBERARK TO SEE IF ITS LOCKED")
    $InputBox.CharacterCasing = 'Upper'
    $InputBox.Add_TextChanged({
    
    If($this.Text -and $InputBox.Text) {
            $ButtonSearch.Enabled = $true
        }
    })

    $form1.Controls.Add($InputBox)
    ############################################## End Inputbox and Inputboxlabel


    
    ############################################## Start Outputbox and outputboxlabel
    $outputBoxLabel.Location = New-Object System.Drawing.Size(20,110)
    $outputBoxLabel.Size = New-Object System.Drawing.Size(150,20)
    $outputBoxLabel.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $outputBoxLabel.Text = "FULL NAME"
    $form1.Controls.Add($outputBoxLabel)
    
    $outputBox.Location = New-Object System.Drawing.Size(20,130)
    $outputBox.Size = New-Object System.Drawing.Size(150,20)
    $outputBox.ScrollBars = "Vertical"
    $outputBox.CharacterCasing = 'Upper'
    $outputBox.ReadOnly = $true
    $outputBox.TabStop = $false
    $form1.Controls.Add($outputBox)
    ############################################## End Outputbox and outputboxlabel



    ############################################## Start Outputbox1 and outputboxlabel1  
    $outputBoxLabel1.Location = New-Object System.Drawing.Size(180,110)
    $outputBoxLabel1.Size = New-Object System.Drawing.Size(150,20)
    $outputBoxLabel1.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $outputBoxLabel1.Text = "NETWORK ID"
    $form1.Controls.Add($outputBoxLabel1)
    
    $outputBox1.Location = New-Object System.Drawing.Size(180,130)
    $outputBox1.Size = New-Object System.Drawing.Size(150,20)
    $outputBox1.ScrollBars = "Vertical"
    $outputBox1.CharacterCasing = 'Upper'
    $outputBox1.ReadOnly = $true
    $outputBox1.TabStop = $false
    $form1.Controls.Add($outputBox1) 
    ############################################## End outputBox1 and outputBoxLabel1


    
    ############################################## Start Outputbox2 and pictureBox  
    $outputBoxLabel2.Location = New-Object System.Drawing.Size(340,110)
    $outputBoxLabel2.Size = New-Object System.Drawing.Size(150,20)
    $outputBoxLabel2.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $outputBoxLabel2.Text = "ENABLED IN AD"
    $form1.Controls.Add($outputBoxLabel2)  
    ############################################## End outputBox2 and pictureBox



    ############################################## Start Outputbox3 and outputboxlabel3  
    $outputBoxLabel3.Location = New-Object System.Drawing.Size(20,210)
    $outputBoxLabel3.Size = New-Object System.Drawing.Size(150,20)
    $outputBoxLabel3.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $outputBoxLabel3.Text = "USER SUSPENDED "
    $form1.Controls.Add($outputBoxLabel3)
    
    $outputBox3.Location = New-Object System.Drawing.Size(20,230)
    $outputBox3.Size = New-Object System.Drawing.Size(150,20)
    $outputBox3.ScrollBars = "Vertical"
    $outputBox3.CharacterCasing = 'Upper'
    $outputBox3.ReadOnly = $true
    $outputBox3.TabStop = $false
    $form1.Controls.Add($outputBox3) 
    ############################################## End outputBox3 and outputBoxLabel3
    
    
    
    
    ############################################## Start Outputbox4 and outputboxlabel4
    $outputBoxLabel4.Location = New-Object System.Drawing.Size(180,210)
    $outputBoxLabel4.Size = New-Object System.Drawing.Size(150,20)
    $outputBoxLabel4.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $outputBoxLabel4.Text = "FAILED LOGINS"
    $form1.Controls.Add($outputBoxLabel4)
    
    $outputBox4.Location = New-Object System.Drawing.Size(180,230)
    $outputBox4.Size = New-Object System.Drawing.Size(150,20)
    $outputBox4.ScrollBars = "Vertical"
    $outputBox4.CharacterCasing = 'Upper'
    $outputBox4.ReadOnly = $true
    $outputBox4.TabStop = $false
    $form1.Controls.Add($outputBox4) 
    ############################################## End outputBox4 and outputBoxLabel4

    
    
    ############################################## Start form1   
    $form1.ClientSize = New-Object System.Drawing.Size(800,600)
	$form1.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$form1.Name = "form1"
    $form1.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
	$form1.Text = "CYBERARK USER ACCOUNT STATUS TOOL"
    $form1.FormBorderStyle = 'Fixed3D'
    $form1.SizeGripStyle = 'Hide'
    $form1.MinimizeBox = $false
    $form1.MaximizeBox = $false
    $form1.StartPosition = "CenterScreen"
    $form1.TopMost = $true
	$form1.add_Load($FormEvent_Load)
    $form1.Icon = [System.Convert]::FromBase64String('AAABAAIAEBAAAAAAIABoBAAAJgAAACAgAAAAACAAqBAAAI4EAAAoAAAAEAAAACAAAAABACAAAAAAAEAEAAAAAAAAAAAAAAAAAAAAAAAA////Af///wH///8B////Af///wH///8Bt309Ibd9PbGsXgC9rF0AJ////wH///8B////Af///wH///8B////Af///wH///8B////Af///wG3fT0Ht309fbd9PfW3
    fT3/rF4A/6xdAPmsXQCFrF0AC////wH///8B////Af///wH///8B////Af///wG3fT1Jt30927d9Pf+3fT3/t309/6xeAP+sXQD/rF0A/6xdAN+sXQBP////Af///wH///8B////Abd9PSG3fT2vt309/7d9Pf+3fT3/t309/7d9Pf+sXgD/rF0A/6xdAP+sXQD/rF0A/6xdALOsXQAh////Af///wGwaRbp
    tXg097d9Pf+3fT3/t309/7d9Pe23fT15rF0AeaxdAPOsXQD/rF0A/6xdAP+sXQD/rF0A7////wH///8BrF0A/6xdAPuvZxL3tHYs8bd9PYe3fT0R////Af///wGsXQAdrF0Ap6xdAP+sXQD/rF0A/6xdAPv///8B////AaxdAP+sXQD/rF0A/5xiKetgXVyTYF1cDf///wH///8BnpuZA56bmV+mek53rF0A
    0axdAP+sXQD/////Af///wGsXQD/rF0A/6xdAP+cYinrYF1c/2BdXONgXVxPnpuZP56bmc2em5n/npuZVaxdAAWsXQBtrF0A7////wH///8BrF0A/6xdAP+sXQD/nWIo52BdXP9gXVz/YF1c/5uYlv+em5n/npuZ/56bmVX///8B////AaxdABX///8B////AaxdAP+sXQD/rF0A/51iKOdgXVz/YF1c/2Bd
    XP+bmJb/npuZ/56bmf+em5lV////Af///wH///8B////Af///wGsXQD/rF0A/65kDfO0dy/vj3FV62JeXf1gXVz/m5iW/56bmf+iiW/vq2QZs6xdAB////8B////Af///wH///8BrWAG87NzKvO3fT3/t309/7d9Pf+te0bxdWZa8Z2NhPGpbCzvrF0A/6xdAP+sXQDzrF0AcaxdAAP///8B////AbZ8O2G3
    fT3jt309/7d9Pf+3fT3/t309/7d9Pf2sXQD7rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQCJ////Af///wH///8Bt309C7d9PX23fT3zt309/7d9Pf+3fT3/rF4A/6xdAP+sXQD/rF0A/6xdAMOsXQBD////Af///wH///8B////Af///wH///8Bt309Gbd9PZ23fT39t309/6xeAP+sXQD/rF0AxaxdAEX///8B
    ////Af///wH///8B////Af///wH///8B////Af///wH///8Bt309L7d9PbusXgDJrF0ASf///wH///8B////Af///wH///8B////AQAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8oAAAAIAAAAEAAAAABACAAAAAAAIAQAAAAAAAAAAAA
    AAAAAAAAAAAA////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wG3fT0ft309r6xfAMusXQAv////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af//
    /wH///8B////Af///wG3fT0Ht309e7d9Pfe3fT3/rF8A/6xdAP2sXQCPrF0AD////wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8Bt309Sbd9Pdu3fT3/t309/7d9Pf+sXwD/rF0A/6xdAP+s
    XQDnrF0AWf///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8Bt309Hbd9Pau3fT3/t309/7d9Pf+3fT3/t309/6xfAP+sXQD/rF0A/6xdAP+sXQD/rF0AvaxdACn///8B////Af///wH///8B////Af///wH///8B
    ////Af///wH///8B////Af///wH///8B////Af///wH///8Bt309B7d9PXm3fT31t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/rF8A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A+axdAIWsXQAL////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Abd9PUW3fT3Zt309
    /7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+sXwD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAOGsXQBP////Af///wH///8B////Af///wH///8B////Af///wH///8B////Abd9PR23fT2rt309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/6xfAP+sXQD/rF0A/6xd
    AP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQCzrF0AIf///wH///8B////Af///wH///8B////Abd9PQe3fT15t3099bd9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/rF8A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD3rF0Ae6xdAAf/
    //8B////Af///wH///8BsW4dwbd9PP+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pa2sXgCprF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0Az////wH///8B////Af///wGsXQD/rF4A57BsGuO3fDz/t309/7d9Pf+3fT3/
    t309/7d9Pf+3fT3/t309/7d9Pbu3fT01////Af///wGsXQA/rF0A0axdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQDx////Af///wH///8B////AaxdAP+sXQD/rF0A/6xeAPOvahHntno5/7d9Pf+3fT3/t309/7d9Pcm3fT1B////Af///wH///8B////Af///wGsXQAFrF0A
    a6xdAO+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAPH///8B////Af///wH///8BrF0A/6xdAP+sXQD/rF0A/6xdAP+tXgD5r2cA7bV5ON23fT1R////Af///wH///8B////Af///wH///8B////Af///wH///8BrF0AFaxdAJusXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A////
    /wH///8B////Af///wGsXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/jGpa02BdXHlgXVwF////Af///wH///8B////Af///wH///8B////Af///wH///8BnpuZEah+a2usXQDHrF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/////Af///wH///8B////AaxdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+K
    aVvZYF1c/2BdXNFgXVw1////Af///wH///8B////Af///wH///8BnpuZB56bmXeem5nxnpuZq////wGsXQBhrF0A6axdAP+sXQD/rF0A/6xdAP////8B////Af///wH///8BrF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/4ppW9lgXVz/YF1c/2BdXP1gXVyRYF1cDf///wH///8B////AZ6bmVWem5nf
    npuZ/56bmf+em5mr////Af///wGsXQAPrF0Aj6xdAPusXQD/rF0A/////wH///8B////Af///wGsXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/i2pb12BdXP9gXVz/YF1c/2BdXP9gXVzjYF1cTZ6bmTWem5nFnpuZ/56bmf+em5n/npuZ/56bmav///8B////Af///wH///8BrF0AK6xdAL2sXQD/////
    Af///wH///8B////AaxdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+MaVrPYF1c/2BdXP9gXVz/YF1c/2BdXP9gXVz/mZaU/56bmf+em5n/npuZ/56bmf+em5n/npuZq////wH///8B////Af///wH///8B////AaxdAFX///8B////Af///wH///8BrF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/4xp
    Ws9gXVz/YF1c/2BdXP9gXVz/YF1c/2BdXP+YlpT/npuZ/56bmf+em5n/npuZ/56bmf+em5mr////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wGsXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/jGlaz2BdXP9gXVz/YF1c/2BdXP9gXVz/YF1c/5iWlP+em5n/npuZ/56bmf+e
    m5n/npuZ/56bmav///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////AaxdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+NalrPYF1c/2BdXP9gXVz/YF1c/2BdXP9gXVz/mJaU/56bmf+em5n/npuZ/56bmf+em5n/npuZq////wH///8B////Af///wH///8B////Af///wH///8B
    ////Af///wH///8BrF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD9rmYA17R7PumCcWffYF1c/2BdXP9gXVz/YF1c/2BdXP+YlpT/npuZ/56bmf+em5n/npuZ/56amP+oe2axrF0AJ////wH///8B////Af///wH///8B////Af///wH///8B////Af///wGsXQD/rF0A/6xdAP+sXQD/rWIA27V3NPe3fT3/t309
    /7d9Pf+qfVfPamNh+WBdXP9gXVz/YF1c/5iWlP+em5n/npuZ/56bmf+lioHhqmAA3axdAP+sXQD5rF0AeaxdAAX///8B////Af///wH///8B////Af///wH///8B////AaxdAP+sXQD/rF8A47NzK+u3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+2fT/vjHVm12BdXP9gXVz/mJaU/56bmf+ikozvqmUs0axd
    AP+sXQD/rF0A/6xdAP+sXQD/rF0A0axdADX///8B////Af///wH///8B////Af///wH///8BrV4A77FtHN23fTz/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/r31P1XBnY/GakY/5qW9NzaxdAPusXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/axdAI+sXQAL////Af///wH/
    //8B////Af///wG2ejh7t3098bd9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t30/96xfAO+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAN+sXQBF////Af///wH///8B////Af///wG3fT0Vt309lbd9Pf23fT3/t309/7d9Pf+3fT3/
    t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/rF8A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0AwaxdAD////8B////Af///wH///8B////Af///wH///8Bt309J7d9PbO3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/7d9Pf+sXwD/rF0A/6xdAP+sXQD/rF0A
    /6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0AyaxdAEP///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Abd9PUO3fT3Pt309/7d9Pf+3fT3/t309/7d9Pf+3fT3/t309/6xfAP+sXQD/rF0A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0AyaxdAEn///8B////Af///wH///8B////Af//
    /wH///8B////Af///wH///8B////Af///wH///8B////Abd9PQO3fT1ht30957d9Pf+3fT3/t309/7d9Pf+3fT3/rF8A/6xdAP+sXQD/rF0A/6xdAP+sXQD/rF0AyaxdAEn///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wG3
    fT0Lt309gbd9PfW3fT3/t309/7d9Pf+sXwD/rF0A/6xdAP+sXQD/rF0Az6xdAEn///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8Bt309G7d9PZ+3fT3/t309/6xfAP+sXQD/rF0Az6xdAFH///8B
    ////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Abd9PTG3fT29rF8A06xdAFH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////Af///wH///8B////
    AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    ############################################## End form1



    ############################################## Start Status Labels

    $ToolVersion.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left 
	$ToolVersion.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$ToolVersion.Location = New-Object System.Drawing.Point(757,580)
	$ToolVersion.Name = "ToolVersion"
	$ToolVersion.Size = New-Object System.Drawing.Size(100,21)
    $ToolVersion.Text = "$toolver"
	$ToolVersion.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $form1.Controls.Add($ToolVersion)

    $ADConnStatus.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left 
	$ADConnStatus.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
    $ADConnStatus.Location = New-Object System.Drawing.Point(475,580)
	$ADConnStatus.Name = "ADConnStatus"
	$ADConnStatus.Size = New-Object System.Drawing.Size(272,21)
	$ADConnStatus.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $form1.Controls.Add($ADConnStatus)
               
    $PSMStatus.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left 
	$PSMStatus.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
	$PSMStatus.Location = New-Object System.Drawing.Point(263,580)
    $PSMStatus.Name = "PSMStatus"

	$PSMStatus.Size = New-Object System.Drawing.Size(210,21)
	$PSMStatus.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $PSMStatus.BorderStyle = 'FixedSingle'
    $form1.Controls.Add($PSMStatus)
        
    $VaultStatus.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left 
	$VaultStatus.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation 
    $VaultStatus.Location = New-Object System.Drawing.Point(1,580)
	$VaultStatus.Name = "VaultStatus"
    $VaultStatus.Size = New-Object System.Drawing.Size(260,21)
	$VaultStatus.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $form1.Controls.Add($VaultStatus)
    ############################################## End Status Labels



    ############################################## Start Search, Exit, Activate/Deactivate, Help and EasterEgg buttons
    $ButtonHelp.Location = New-Object System.Drawing.Size(675,3)
    $ButtonHelp.TabIndex = 2
    $ButtonHelp.Size = New-Object System.Drawing.Size(110,25)
    $ButtonHelp.TextImageRelation = "ImageAboveText"
    $ButtonHelp.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $ButtonHelp.Text = "Help"
    $tooltip1.SetToolTip($ButtonHelp, "CLICK TO VIEW THE DOCUMENTATION.")
    $ButtonHelp.Add_Click($handler_btnHelp_Click)
    $form1.Controls.Add($ButtonHelp)

    $ButtonHelpYou.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(0,255,255,255)
    $ButtonHelpYou.Location = New-Object System.Drawing.Point(745,582)
    $ButtonHelpYou.Size = New-Object System.Drawing.Size(17,17)
    $ButtonHelpYou.TextImageRelation = "ImageAboveText"
    $ButtonHelpYou.DataBindings.DefaultDataSourceUpdateMode = 0
    $ButtonHelpYou.FlatAppearance.BorderSize = 0
    $ButtonHelpYou.FlatStyle = 0
    $ButtonHelpYou.ForeColor = "Black"
    $ButtonHelpYou.Text = "v"
    $ButtonHelpYou.Add_Click($handler_btnHelpYou_Click)
    $form1.Controls.Add($ButtonHelpYou)

    $ButtonSearch.Location = New-Object System.Drawing.Size(560,30)
    $ButtonSearch.TabIndex = 1
    $ButtonSearch.Size = New-Object System.Drawing.Size(110,80)
    $ButtonSearch.TextImageRelation = "ImageAboveText"
    $ButtonSearch.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $ButtonSearch.Text = "Search"
    $tooltip1.SetToolTip($ButtonSearch, "CLICK TO QUERY A USER ACCOUNT WITHIN CYBERARK.")
    $ButtonSearch.Add_Click($handler_btnSearch_Click)
    #region Binary Data
    $ButtonSearch.Image = [System.Convert]::FromBase64String('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')
    #endregion
    $form1.Controls.Add($ButtonSearch) 

    $ButtonExit.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation
    $ButtonExit.TabIndex = 3
    $ButtonExit.Location = New-Object System.Drawing.Size(675,30) 
    $ButtonExit.Size = New-Object System.Drawing.Size(110,80)
    $ButtonExit.TextImageRelation = "ImageAboveText"
    $ButtonExit.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $ButtonExit.Text = "Exit"
    $tooltip1.SetToolTip($ButtonExit, "CLICK EXIT TO QUIT THE UTILITY.")
    $ButtonExit.Add_Click($handler_btnCancel_Click)
    #region Binary Data
	$ButtonExit.Image = [System.Convert]::FromBase64String('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')
    #endregion
    $form1.Controls.Add($ButtonExit)

    $ButtonActivate.Location = New-Object System.Drawing.Size(560,180) 
    $ButtonActivate.Size = New-Object System.Drawing.Size(110,80)
    $ButtonActivate.TextImageRelation = "ImageAboveText"
    $ButtonActivate.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $ButtonActivate.Text = "Activate"
    $tooltip1.SetToolTip($ButtonActivate, "CLICK TO ACTIVATE A USER ACCOUNT WITHIN CYBERARK.")
    $ButtonActivate.Add_Click($handler_btnActivate_Click)
    #region Binary Data
    $ButtonActivate.Image = [System.Convert]::FromBase64String('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')
    #endregion

    $ButtonReset.DataBindings.DefaultDataSourceUpdateMode = [System.Windows.Forms.DataSourceUpdateMode]::OnValidation
    $ButtonReset.Location = New-Object System.Drawing.Size(675,180) 
    $ButtonReset.Size = New-Object System.Drawing.Size(110,80)
    $ButtonReset.TextImageRelation = "ImageAboveText"
    $ButtonReset.font = New-Object System.Drawing.Font("arial",10,[System.Drawing.FontStyle]::Bold)
    $ButtonReset.Text = "Reset Account"
    $tooltip1.SetToolTip($ButtonReset, "CLICK TO DEACTIVATE THEN ACTIVATE A USER ACCOUNT WITHIN CYBERARK.")
    $ButtonReset.Add_Click($handler_btnReset_Click)
    #region Binary Data
	$ButtonReset.Image = [System.Convert]::FromBase64String('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')
    #endregion

    ############################################## End Search, Exit, Activate and Deactivate buttons

    
    #Save the initial state of the form
	$InitialFormWindowState = $form1.WindowState
	#Init the OnLoad event to correct the initial state of the form
	$form1.add_Load($Form_StateCorrection_Load)
	#Show the Form
	return $form1.ShowDialog()

    }



#Call OnApplicationLoad to initialize
if(OnApplicationLoad -eq $true)
{
	#Create the form
	GenerateForm | Out-Null
	
    #Perform cleanup
	OnApplicationExit

}else{

    # Get date/time for notification and logging
    $now = Get-Date -UFormat "%m/%d/%Y - %H:%M:%S"

    # Define variables for email from StationSuspendedTool.ini
    [string]$SMTPServer = $FileContent["Email"]["SMTPServer"]
    [string]$SMTPFrom = $FileContent["Email"]["SMTPFrom"]
    [string]$SMTPTo = $FileContent["Email"]["SMTPTo"]

    # Define the subject of the email
    $messageSubject = "$AuthorizedUserName ATTEMPTED TO EXECUTE THE CYBERARK STATION SUSPENDED TOOL"

    # Define the body of the message
    $body = "`r`n`r`nUNAUTHORIZED ACCESS ATTEMPT BY $AuthorizedUserName FROM MACHINE NAME $CompName AT $now.`r`n`r`r`n`r"
    
    
    #####################################################################################################################################
    #####################################################################################################################################
    # IMPORTANT: The machine running this from must have the ability to send email for the email notifications to work correctly.
    #####################################################################################################################################
    #####################################################################################################################################
    
    # Send the email message
    # Uncomment the line below to enable emails being sent for unauthorized attempts to execute this utility.
    #send-mailmessage -from "$smtpFrom" -to $smtpTo -subject "$messageSubject" -body "$body" -smtpServer "$smtpserver"
        
    # Display error dialog popup
    $message = "$AuthorizedUserName IS NOT AUTHORIZED TO USE THIS UTILITY.`r`n`r`nUNAUTHORIZED ACCESS ATTEMPT BY $AuthorizedUserName FROM MACHINE NAME $CompName AT $now HAS BEEN LOGGED AND REPORTED."
    $caption = "UNAUTHORIZED ACCESS ATTEMPT"
    $buttons = [System.Windows.Forms.MessageBoxButtons]::OK
    $icon = [System.Windows.Forms.MessageBoxIcon]::Warning
    $msgbox2 = [System.Windows.Forms.MessageBox]::Show($message,$caption,$buttons,$icon)
    Break
}