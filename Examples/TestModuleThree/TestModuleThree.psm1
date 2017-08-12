<#
This example show how you can extend Configuration to allow AES key 
support for encryption instead of sticking with the DPAPI.

AES key encryption will allow the same config to be decrypted by 
multiple accounts on multiple machines, provided they have the key.

This also includes the Set-EncryptionPreference function example, in case you
would like to have your module default to using either DPAPI or AES with a specific
key ( @(1..16) is there to provide a basic byte array as an example )
#>

# Assume I have a mandatory API key pair (Client ID & Secrets)....

function ImportConfiguration {
    $Configuration = Get-Secrets
    if(!$Configuration.ClientID -or !$Configuration.ClientSecrets) {
        Write-Warning "Thanks for using the Acme Industries Module, please run Set-AimConfiguration to configure."
        throw "Module not configured. Run Set-AimConfiguration"
    }
    $Configuration
}
function Get-Secrets {
    function Decrypt {
        [cmdletbinding()]
        Param
        (
            [parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)]
            [SecureString]
            $SecureString
        )
        [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString))
    }
    Import-Configuration | Select-Object @{N = "ClientID";E = {Decrypt $_.ClientID}},@{N = "ClientSecrets";E = {Decrypt $_.ClientSecrets}}
}

function Set-Secrets {
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [SecureString]$ClientID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [SecureString]$ClientSecrets
    )
    end {
        $PSBoundParameters | Export-Configuration
    }
}

function Set-EncryptionPreference {
    Param
    (
        [parameter(Mandatory = $false,Position = 0)]
        [ValidateSet("DPAPI","Key")]
        [String]
        $Method = "DPAPI",
        [parameter(Mandatory = $false,Position = 1)]
        [Byte[]]
        $Key
    )
    $script:EncryptionMethod = $Method
    if ($PSBoundParameters.Keys -contains "Key") {
        $script:EncryptionKey = $Key
    }
}

function SecureString {
    <#
       .Synopsis
          Creates a new SecureString from PlainText
       .Description
          This is convenience function to shrink the full command
       .Parameter String
          The String to convert to a SecureString
    #>
    param([string]$String)
    ConvertTo-SecureString "$String" -AsPlainText -Force
}


# Set a default key, add Metadata converters to allow use of AES keys, then test to see if the configuration is set:
try {
    Set-EncryptionPreference -Method Key -Key ([Byte[]]@(1..16)) # SAMPLE KEY - DON'T USE SOMETHING THIS SIMPLE IF YOU'RE GOING TO USE AN AES KEY!!!
    Add-MetadataConverter -Converters @{
        [PSCredential] = {
            $encParams = @{}
            if ($script:EncryptionMethod -ne "DPAPI" -and $script:EncryptionKey -is [System.Byte[]]) {
                $encParams[$script:EncryptionMethod] = $script:EncryptionKey
                'PSCredential "{0}" (ConvertTo-SecureString "{1}" -Key (Get-Key))' -f $_.UserName, (ConvertFrom-SecureString $_.Password @encParams)
            }
            else {
    
                'PSCredential "{0}" "{1}"' -f $_.UserName, (ConvertFrom-SecureString $_.Password)
            }
        }
        "PSCredential" = {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword","EncodedPassword")]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingUserNameAndPasswordParams","")]
            param(
                [string]$UserName,
                [string]$EncodedPassword
            )
            $encParams = @{}
            if ($script:EncryptionMethod -ne "DPAPI" -and $script:EncryptionKey -is [System.Byte[]]) {
                $encParams[$script:EncryptionMethod] = $script:EncryptionKey
            }
            New-Object PSCredential $UserName, (ConvertTo-SecureString $EncodedPassword @encParams)
        }

        [SecureString] = {
            $encParams = @{}
            if ($script:EncryptionMethod -ne "DPAPI" -and $script:EncryptionKey -is [System.Byte[]]) {
                $encParams[$script:EncryptionMethod] = $script:EncryptionKey
            }
            'Secure "{0}"' -f (ConvertFrom-SecureString $_ @encParams)
        }
        "Secure" = {
            param([string]$String)
            $encParams = @{}
            if ($script:EncryptionMethod -ne "DPAPI" -and $script:EncryptionKey -is [System.Byte[]]) {
                $encParams[$script:EncryptionMethod] = $script:EncryptionKey
            }
            ConvertTo-SecureString $String @encParams
        }
    }
    $null = ImportConfiguration
    Get-Secrets
}
catch {
    # Hide the error on import, just warn them
    Write-Host "You must configure module to avoid this warning on first run. Use Set-Secrets" -ForegroundColor Black -BackgroundColor Yellow
}