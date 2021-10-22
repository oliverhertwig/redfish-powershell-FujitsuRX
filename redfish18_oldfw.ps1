clear
$version = "0.18"
$user = $env:UserName
$domain = $env:USERDOMAIN
$computer = $env:ComputerName
$workdir = Get-Location
$date = Get-date
$time = (get-date).ToString('T')
$date = $date.ToString("d", $locale)
$locale = New-Object System.Globalization.CultureInfo("de-DE")
$Global:ProgressPreference = 'SilentlyContinue'
$logtarget = "$workdir\irmckonfiglog_$(get-date -f yyyy-MM-dd).txt"
$csvoutput = "$workdir\irmckonfigchecklist_$(get-date -f yyyy-MM-dd).csv"
$irmcsrclist = "$workdir\inputlistm4test.csv"
$header = "Servername;iRMC_DNS;Step;Status;Statuscode"
$RedfishSessionResponse = ""
[string[]]$RZMSDNSIP = @("10.232.0.194","10.232.0.197","10.232.0.199")
[string[]]$RZMSNTPIP = @("10.232.0.194","10.232.0.197")
[string[]]$RZDDNSIP = @("10.39.0.18","10.39.0.19","10.39.0.20")
[string[]]$RZDNTPIP = @("10.39.0.18","10.39.0.19")

# Uri Variablen

 $irmcDNSBaseURL = "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Dns/"
 $irmcDNSServerURL = "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Dns/DnsServers/"
 $irmcLANURL = "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Lan/"
 $irmcNTPBaseURL = "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time/"  #NTP RedfishAPI32Specification 174
 $irmcNTPServerURL ="Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time/NtpServers/"
 $irmcAccountURL = "AccountService/Accounts" # Accounts RedfishAPI32Specification 198
 $irmcAVRURL = "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/VideoRedirection/" # AVR RedfishAPI32Specification 153
 $irmcWebUIURL ="Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/WebUI/" # WebUI RedfishAPI32Specification 154
 $irmcServerManagementURL = "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/ServerManagement/" # ServerManagement RedfishAPI32Specification 156
 $irmcNetworkServiceURL= "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/NetworkServices/" # NetworkServices RedfishAPI32Specification 167
 $irmcEthURL = "Managers/iRMC/EthernetInterfaces/0" # Eth RedfishAPI32Specification 134
 $irmcSystemURL = "Systems/0/Oem/ts_fujitsu/System" # System RedfishAPI32Specification 109

# Benötigt, da wir ein Self-signed cert auf dem iRMC haben
#https://blog.ukotic.net/2017/08/15/could-not-establish-trust-relationship-for-the-ssltls-invoke-webrequest/

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

<# 
Function dumpdata Funktion zum einfachen Schreiben von Daten in eine Datei
.NOTES 
   Basiert auf Funktion "Write-Log" von Jason Wasser @wasserja 
#> 
function dumpdata 
{ 
    [CmdletBinding()] 
    #[Alias('dcsv')] 
    [OutputType([int])] 
    Param 
    ( 
        # String, der in die CSV-Datei geschrieben wird 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=0)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("DumpContent")] 
        [string]$Payload, 
 
        # Pfad zur CSV-Datei
        [Parameter(Mandatory=$false, 
                   ValueFromPipelineByPropertyName=$true, 
                   Position=1)] 
        [Alias('DumpPath')] 
        #[string]$Ziel="$workdir\irmcchecker_$(get-date -f yyyy-MM-dd).txt", 
        [string]$Ziel,

        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
    } 
    Process 
    { 
         
        if ((Test-Path $Ziel) -AND $NoClobber) { 
            Write-Warning "Der Pfad zu $Path existiert bereits, und NoClobber ist gesetzt. Loeschen Sie entweder die Datei oder geben Sie einen neuen Namen an." 
            Return 
            } 
          
        # Falls Datei nicht existiert, lege die Datei an!
        elseif (!(Test-Path $Ziel)) { 
            $NewLogFile = New-Item $Ziel -Force -ItemType File 
            #if ($Ziel = "$workdir\irmccheckerlist_$(get-date -f yyyy-MM-dd).csv"){
                # Schreibe Spaltenueberschriften in CSV-Datei
                #Write-Output "$header" | Out-File -FilePath $Ziel
            #}
        } 
 
        else { 
            # Hier passiert nichts 
        } 
 
        # Schreibe in Datei 
              Write-Output "$Payload" | Out-File -FilePath $Ziel -Append 
    } 
    End 
    { 
    } 
}

# Abfrage, für welche Site Script prüfen soll - wird benötigt, um aus der Eingabedatei die nicht benötigten Server auszufiltern
$sitecode = Read-Host -Prompt 'Für welche Site sollen die iRMC geprüft werden? RZMS/RZD?'
dumpdata -Payload "Sitecode ist $sitecode" -Ziel $logtarget
write-host "Sitecode ist $sitecode`r`n"

# $Credentials = Get-Credential -Message "Enter iRMC Creds" - hier nur als Referenz für mögliche Methoden

# Vorbelegte Creds - hier nur als Referenz für mögliche Methoden
# $User = "admin"
# $PWord = ConvertTo-SecureString -String "admin" -AsPlainText -Force
# $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

# Ist noch kein xml-File mit den Credentials vorhanden, muss es angelegt werden!

If (!(Test-Path $workdir\SecureCredentials.xml)){ 
    Write-Host "XML-Datei mit Credentials muss angelegt werden, bitte Pop-Up beachten!`r`n"
    Get-Credential –Credential (Get-Credential) | EXPORT-CLIXML "$workdir\SecureCredentials.xml"
}
# Einlesen des xml mit den Credentials

$Credentials = IMPORT-CLIXML "$workdir\SecureCredentials.xml"

# Supersicher ist das nicht - die Variablen werden mit Klartextwerten belegt:
# To-Do: Checken, ob man das nicht sicherer machen kann!

$RESTAPIUser = $Credentials.UserName
$RESTAPIPassword = $Credentials.GetNetworkCredential().Password

$params = @{
 "UserName"="$RESTAPIUser";
 "Password"="$RESTAPIPassword";
}

# warum nicht $csvoutput mit if checken? prüfen
if ($Ziel = "$workdir\irmckonfigchecklist_$(get-date -f yyyy-MM-dd).csv"){
                # Schreibe Spaltenueberschriften in CSV-Datei
                Write-Output "$header" | Out-File -FilePath $Ziel
}

dumpdata -payload "********************************************" -Ziel $logtarget
dumpdata -payload "--------------------------------------------" -Ziel $logtarget
dumpdata -Payload "Version: $version" -Ziel $logtarget
dumpdata -Payload "Datum: $date" -Ziel $logtarget
dumpdata -Payload "Uhrzeit: $time" -Ziel $logtarget
dumpdata -Payload "Aufrufender Benutzer: $user" -Ziel $logtarget
dumpdata -Payload "Domäne/Computername: $domain" -Ziel $logtarget
dumpdata -Payload "Computername: $computer" -Ziel $logtarget
dumpdata -payload "********************************************" -Ziel $logtarget

$InputFileCSV = Import-Csv $irmcsrclist -Delimiter ";"

foreach ($line in $InputFileCSV) {
    
    $irmcName = $line.Servername
    #$irmcDNS = $line.iRMC_DNS+".irmc.rz.justiz.nrw.de"
    ###ohetest
    $irmcDNS = $line.iRMC_DNS+".local"
    Write-Host "`r`nBehandle $irmcName mit iRMC DNS Name  $irmcDNS`r`n" -ForegroundColor Cyan
    $irmcBaseUrl = "https://" + $irmcDNS
    $RedfishBaseURL = "https://" + $irmcDNS + "/redfish/v1/"
    $RedfishSessionURL = $RedfishBaseURL + "SessionService/Sessions/"

    # Preflight checks
    write-host "Start Preflight-Check gegen $irmcName mit temp. DNS $irmcDNS`r`n" -ForegroundColor Green
    dumpdata -payload "***********************************************************************" -Ziel $logtarget
    dumpdata -payload "Start Preflight-Check gegen $irmcName mit temp. DNS $irmcDNS" -Ziel $logtarget

    if ($irmcName -match $sitecode -eq "True"){
        #$PSDefaultParameterValues['Test-NetConnection:InformationLevel'] = 'Quiet'
        try{
            ###ohetest
            #$testconnection = (Test-NetConnection -ComputerName $irmcDNS -ErrorAction SilentlyContinue).PingSucceeded 2> $NULL
            $testconnection = (Test-Connection -ComputerName $irmcDNS -Count 1 -ErrorAction SilentlyContinue).Succeeded 2> $NULL
            ###ohetest
            #if ($testconnection -eq "true"){
            if ($testconnection -eq "Success"){
                write-host "$irmcDNS ($irmcName) erreichbar!" -ForegroundColor Green
                checkirmc $irmcDNS
            }else{
                bogusdump
            }
        }catch{
             Write-Host "Fehler beim Test der Netzwerkverbindung zu $irmcDNS!"
             dumpdata -Payload "Fehler beim Test der Netzwerkverbindung zu $irmcDNS!" -Ziel $logtarget
             $_.Exception.ToString()
             $error[0] | Format-List -Force   
        }

    }


    
    function checkirmc{
    param ([string] $irmcDNS)
        write-host "Pruefe, ob Redfish Session Collection von iRMC von $irmcDNS verfuegbar ist!"
        write-host "Base URL ist $RedfishBaseURL"
        write-host "irmcBaseURL ist $irmcBaseURL"
        write-host "***************************************************`r`n"
        # dumpdata -payload "Pruefe, ob Redfish Session Collection von iRMC von $irmcIP verfuegbar ist!" -Ziel $logtarget
        # dumpdata -payload "Ist auch check, ob Creds passen!" -Ziel $logtarget
   
        # Check, ob Session Collection in der API ansprechbar

        try
            {
                #$RedfishCollectionCheck = Invoke-RestMethod -Uri $RedfishBaseURL -Credential $Credentials -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"}
                # Credentials hier nicht benötigt!!
                $RedfishCollectionCheck = Invoke-RestMethod -Uri $RedfishBaseURL -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"}
                write-host "OK - API antwortet!"
                dumpdata -payload "OK- API antwortet!" -Ziel $logtarget
                dumpdata -payload "Anmeldung an SessionCollection von $irmcDNS erfolgreich!" -Ziel $logtarget
                dumpdata -Payload "$irmcName;$irmcDNS;SC_Check;OK" -Ziel $csvoutput
            }
        catch 
            {
                Write-Host "Fehler beim Check auf Session Collection!"
                dumpdata -Payload "Fehler beim Check auf Session Collection!" -Ziel $logtarget
                $_.Exception.ToString()
                $error[0] | Format-List -Force
                $StatusCode = $_.Exception.Response.StatusCode.value__
                write-host "Statuscode ist $StatusCode"
                dumpdata -Payload "$irmcName;$irmcDNS;SC_Check;Fehler;$StatusCode" -Ziel $csvoutput
                dumpdata -Payload "Statuscode ist $StatusCode" -Ziel $logtarget
                dumpdata -payload "Anmeldung an SessionCollection von $irmcDNS nicht erfolgreich!" -Ziel $logtarget
            }        

            # ***POST zum Starten einer Session***
        try
            {

                sleep -Milliseconds 1000
                # Invoke-WebRequest wg. Verarbeitung der zurückgegebenen Header
                $RedfishSessionResponse = Invoke-WebRequest -Uri $RedfishSessionURL -Credential $Credentials -Method Post -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"} -Body ($params|ConvertTo-Json)
                dumpdata -Payload "$irmcName;$irmcDNS;SPOST_Check;OK" -Ziel $csvoutput
            }
        catch
            {
                
                Write-Host "Fehler beim Aufbau der Session!"
                Write-host "Ggf. Falsche Credentials?`r`n"
                dumpdata -Payload "Fehler beim Aufbau der Session zu $irmcDNS!" -Ziel $logtarget
                $_.Exception.ToString()
                $error[0] | Format-List -Force
                $StatusCode = $_.Exception.Response.StatusCode.value__
                dumpdata -Payload "$irmcName;$irmcDNS;SPOST_Check;Fehler;$StatusCode" -Ziel $csvoutput
                write-host "Statuscode ist $StatusCode"
                dumpdata -Payload "Statuscode ist $StatusCode" -Ziel $logtarget
                dumpdata -payload "User $RESTAPIUser konnte sich mit $RESTAPIPassword NICHT an $irmcDNS anmelden!" -Ziel $logtarget
            }        
    
            $Global:SessionLocation = $RedfishSessionResponse.Headers.Location
            # $SessionID = "https://" + $RESTAPIServer + $RedfishSessionResponse.Headers.Location
            $Global:SessionID = "https://" + $irmcDNS + $SessionLocation
    
            # To-Do: Hier ggf. in Zukunft noch Session Rolle und ID hernehmen und anzeigen?
            # Rolle ist wichtig wegen Berechtigungen in der API

            $Global:SessionToken = $RedfishSessionResponse.Headers.'X-Auth-Token'
            # return $SessionToken
            Write-Host "Session Location: " $SessionLocation
            Write-Host "Session Token: " $SessionToken
            write-host "*****************************************"
            write-host "Ende Preflight-Check gegen $irmcName mit temp. DNS $irmcDNS" -ForegroundColor Green
            dumpdata -Payload "Ende Preflight-Check gegen $irmcName mit temp. DNS $irmcDNS" -Ziel $logtarget
            dumpdata -Payload "****************************************************************************" -Ziel $logtarget
            # Start Auslesen FW Version
            #write-host
            #write-host "Start Auslesen FW Version $irmcIP" -ForegroundColor Green
            #dumpdata -Payload "Start Auslesen FW Version $irmcIP" -Ziel $logtarget
            #$Uri = $RedfishBaseURL+$irmcFirmwareURL
            #write-host "Ziel für redfishendpointread ist $Uri"
            #$fwversionresponse = redfishendpointread $Uri $SessionToken
            #$fwversionresponse
            #$etag = $fwversionresponse|select -ExpandProperty "@odata.etag"
            #$etag
            #$fwversion = $fwversionresponse.BMCFirmware
            #$fwbuilddate = $fwversionresponse.BMCFirmwareBuildDate
            #$systemBIOS = $fwversionresponse.SystemBIOS
            #$systemType = $fwversionresponse.SDRRId
            #dumpdata "$irmcName;$irmcIP;$fwversion;$fwbuilddate;$systemBIOS;$systemType" -Ziel $csvoutput
            #write-host "Ende Auslesen FW Version" -ForegroundColor Green
            #dumpdata -Payload "Ende Auslesen FW Version" -Ziel $logtarget
            #cleanexit
            #sleep -Milliseconds 500
            # Ende Auslesen FW Version
   }

function bogusdump{
    write-host "iRMC mit DNS-Name $irmcDNS nicht erreichbar!`r`n" -ForegroundColor Red
    dumpdata -Payload "$irmcName mit $irmcDNS nicht erreichbar" -Ziel $logtarget
    dumpdata -Payload "$irmcName;$irmcDNS;netconnection;Fehler" -Ziel $csvoutput
    exit 0
    }

}


function processirmclist{
    # Datenstruktur
    write-host "`r`nStarte Aufbau Datenstruktur für Zuordnung irmc-MAC zu Servername, IP, Netzmaske und Asset Tag`r`n" -ForegroundColor Green
      
    #$header = 'Servername','MAC','IP','Subnetmask' # Neuer Header für import-csv, da Rühn Header doof, Leerzeichen bäh
    

    If (!(Test-Path $irmcsrclist)){ 
        write-host "Datei $irmcsrclist fehlt - Abbruch!" -ForegroundColor Red
        dumpdata -Payload "Datei $irmcsrclist fehlt - Abbruch!" -Ziel $logtarget
        exit
    }

    $Global:irmcSrcHashTable = @{} # Erstellt eine Hash Table zur Aufname der Paarung MAC zu Name, IP, Subnetzmaske

    # Schleife, um Hash Table zu füllen

    foreach ($line in $InputFileCSV) {
       $tmpdns = $line.iRMC_DNS
       $servername = $line.Servername
       $assettag = $line.Asset_Tag
       
       $Global:irmcSrcHashTable.$tmpdns = @() # legt Array im Hashtable an
       $Global:irmcSrcHashTable.$tmpdns += ($servername)
       $Global:irmcSrcHashTable.$tmpdns += ($tmpdns)
       $Global:irmcSrcHashTable.$tmpdns += ($assettag)
    }
       $irmccount = $Global:irmcSrcHashTable.count
            
       write-host "$irmccount Datensätze gelesen.`r`n" -ForegroundColor Green
       write-host "Erstellung Datenstruktur abgeschlossen.`r`n" -ForegroundColor Green    
      
}

function cleanexit{ # Für Softwaretest - wird immer da eingesetzt, wo ein Breakpoint benötigt wird - meldet so auch die Redfish-Sitzung ab.
param([string] $SessionID)    
    Invoke-RestMethod -Uri $SessionID  -Method Delete -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}
    Remove-Variable * -ErrorAction SilentlyContinue
    exit 0
    }

function redfishendpointread{
param([string] $Uri, $SessionToken)
    Invoke-RestMethod -Uri $Uri  -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}
    } 

function patchredfish{
param([string]$Uri, $etag, $body, $SessionToken)
    $patch = Invoke-WebRequest -Uri $Uri  -Method Patch -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken; "If-Match" = $etag} -Body ($body|ConvertTo-json -Compress)

    if ($patch.StatusCode -eq 200){
            [String]::Format("- PASS, Statuscode {0} Vorgang erfolgreich",$patch.StatusCode)
            $dump = [String]::Format("- PASS, Statuscode {0} Vorgang erfolgreich",$patch.StatusCode)
            dumpdata -Payload $dump -Ziel $logtarget
           
    }else{
            [String]::Format("- FAIL, Statuscode {0} FEHLER",$patch.StatusCode)
    
    }
    
    $response = Invoke-RestMethod -Uri $Uri  -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}
    write-Host "`r`nDie Konfig von $Uri ist jetzt:"
    $response    
    ### Hier den etag neu auslesen und übergeben?
    # $etag = $response|select -ExpandProperty "@odata.etag" 
    # return $etag
}

# ****************************************************************************************************************************************

if (![string]::IsNullOrWhitespace($Global:irmcSrcHashTable.first)) {
    Write-Host "`r`nErster Wert im Hashtable $($Global:irmcSrcHashTable.first) - muss nichts tun!" -ForegroundColor Green
    }else{
    Write-Host "`r`nKeine Daten im Hashtable $($Global:irmcSrcHashTable.first) - lege Datenstruktur an!" -ForegroundColor Yellow
    processirmclist
    }


# irmc-Namen identifizieren
write-host "`r`nStart Konfiguration iRMC Name`r`n" -ForegroundColor Green
$Uri = $RedfishBaseURL+$irmcEthURL

$dnsnameconfigresponse = redfishendpointread $Uri $SessionToken

$myhostname = $dnsnameconfigresponse|select -ExpandProperty "HostName"
# $ethmac = $ethmac.ToLower()
write-host "Der aktuelle aus Redfish ausgelesene Hostname des iRMC Boards ist $myhostname"
write-host "Der Servername aus der Liste zum Redfish Hostame $myhostname ist"$Global:irmcSrcHashTable.$myhostname[0] 
write-host "u. d. DNS-Name aus der Liste ist" $Global:irmcSrcHashTable.$myhostname[1]

Try{
    $irmcname = $Global:irmcSrcHashTable.$myhostname[0]
    $irmctmpdns = $Global:irmcSrcHashTable.$myhostname[1]
    $irmcassettag = $Global:irmcSrcHashTable.$myhostname[2]
    write-host "Der temporäre Name ist $irmctmpdns, der zukünftige Name ist $irmcname. Der Asset Tag ist $irmcassettag.`r`n"
    dumpdata -Payload "Der temporäre Name ist $irmctmpdns, der zukünftige Name ist $irmcname. Der Asset Tag ist $irmcassettag." -Ziel $logtarget
}catch{
        Write-Host "Fehler beim Lookup in Hash Table - System dort nicht vorhanden?" -ForegroundColor Red
        $_.Exception.ToString()
        $error[0] | Format-List -Force
        exit 1
        
 }            

if ($myhostname -ieq $irmctmpdns){
    write-host "Der aktuell konfigurierte Redfish Hostname und der übergebene temp. DNS Name aus der Liste stimmen überein!`r`n" -ForegroundColor Green
    dumpdata -Payload "Der aktuell konfigurierte Redfish Hostname $myhostname und der übergebene temp. DNS Name aus der Liste $irmctmpdns stimmen überein!" -Ziel $logtarget
}else{
    write-host "Der aktuell konfigurierte Redfish Hostname und der übergebene temp. DNS Name aus der Liste stimmen nicht überein!`r`n" -ForegroundColor Red
    dumpdata -Payload "Der aktuell konfigurierte Redfish Hostname $myhostname und der übergebene temp. DNS Name aus der Liste $irmctmpdns stimmen nicht überein!" -Ziel $logtarget
    exit 0
}


# Start iRMC Network Config
dumpdata -Payload "Start IP Konfiguration" -Ziel $logtarget
write-host "Start IP Konfiguration" -ForegroundColor Green
write-host "  Start IPv4 Konfiguration`r`n" -ForegroundColor Green

$Uri = $RedfishBaseURL+$irmcLANURL

# write-host "Uri für LAN ist $Uri"
$lanconfigresponse = redfishendpointread $Uri $SessionToken
# !!! TIL: https://adamtheautomator.com/powershell-json/#Parsing_the_JSON_with_PowerShell
$actualip = $lanconfigresponse.IpV4.IpAddress
$actualgw = $lanconfigresponse.IpV4.DefaultGateway
$actualsn = $lanconfigresponse.IpV4.SubnetMask
write-host "IP ist $actualip, gw ist $actualgw, sn ist $actualsn`r`n"
dumpdata -Payload "Originale IP ist $actualip, gw ist $actualgw, sn ist $actualsn" -Ziel $logtarget
Write-Host "Originale Endpointkonfig:`r`n"
$lanconfigresponse
$etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"
write-host "Etag des Endpoints $Uri ist $etag`r`n"
dumpdata -Payload  "Erster Etag des Endpoints $Uri ist $etag" -Ziel $logtarget

$body = @{}
$data = @{"UseDhcp" = "false";}
$body.Add("IpV4",$data)

patchredfish $Uri $etag $body $SessionToken
sleep -Milliseconds 10000
write-host "DHCP zum ersten mal auf False. Ergebnis:"
$lanconfigresponse

$lanconfigresponse =""
$lanconfigresponse = redfishendpointread $Uri $SessionToken
$etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"

$body = @{}
$data = @{"UseDhcp" = "true";}
$body.Add("IpV4",$data)

patchredfish $Uri $etag $body $SessionToken
sleep -Milliseconds 10000
write-host "DHCP zurück auf True. Ergebnis:"
$lanconfigresponse

$lanconfigresponse =""
$lanconfigresponse = redfishendpointread $Uri $SessionToken
$etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"

$body = @{}
$data = @{"UseDhcp" = "false";
          "IpAddress" = $actualip;
          "SubnetMask" = $actualsn;
          "DefaultGateway" = $actualgw;}
$body.Add("IpV4",$data)

patchredfish $Uri $etag $body $SessionToken
sleep -Milliseconds 5000
write-host "DHCP wieder zurück auf False und IPv4 Werte setzen. Ergebnis:"
$lanconfigresponse

# dumpdata -Payload "Nach Änderung DHCP auf False:" -Ziel $logtarget
# dumpdata -Payload $lanconfigresponse -Ziel $logtarget
# sleep -Milliseconds 2000
# $etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"
# write-host "Etag des Endpoints $Uri ist $etag`r`n"
# dumpdata -Payload  "Etag des Endpoints $Uri ist $etag" -Ziel $logtarget
# dumpdata -Payload "Orginal:" -Ziel $logtarget
# dumpdata -Payload $lanconfigresponse -Ziel $logtarget
# sleep -Milliseconds 2000
# cleanexit $SessionID

# $lanconfigresponse =""

# $lanconfigresponse = redfishendpointread $Uri $SessionToken
# $etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"
# write-host "Etag des Endpoints $Uri ist JETZT $etag`r`n"
# dumpdata -Payload "Etag des Endpoints $Uri ist JETZT $etag" -Ziel $logtarget

#$body = @{}
#$data = @{"IpAddress" = $actualip;
#          "SubnetMask" = $actualsn;
#          "DefaultGateway" = $actualgw;}
#$body.Add("IpV4",$data)
# $lanconfigresponse = redfishendpointread $Uri $SessionToken
# $etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"
# dumpdata -Payload "Ohne Änderungen Etag des Endpoints $Uri ist JETZT $etag" -Ziel $logtarget

#patchredfish $Uri $etag $body $SessionToken
#sleep -Milliseconds 1000

# write-host "Nach Anpassung IP, Subnetmaske und GW`r`n"
# $lanconfigresponse
# dumpdata -Payload "Nach Anpassung IP, Subnetmaske und GW:" -Ziel $logtarget
# dumpdata -Payload $lanconfigresponse -Ziel $logtarget
# sleep -Milliseconds 2000
###
#wg etag nötig?
# $lanconfigresponse = redfishendpointread $Uri $SessionToken
# $etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"
# write-host "Etag des Endpoints $Uri ist JETZT $etag`r`n"
# dumpdata -Payload "Etag des Endpoints $Uri ist JETZT $etag" -Ziel $logtarget
$lanconfigresponse =""
write-host "  Ende IPv4 Konfiguration`r`n" -ForegroundColor Green
cleanexit $SessionID
write-host "  Start IPv6 Konfiguration`r`n" -ForegroundColor Green
### Etag neu einlesen, da komischerweise nach Nachtrag der anderen Infos in v4 Body RF über etag meckert
$lanconfigresponse = redfishendpointread $Uri $SessionToken
$etag = $lanconfigresponse|select -ExpandProperty "@odata.etag"
$body = @{}
$data = @{"Enabled" = "false"}
$body.Add("IpV6",$data)
patchredfish $Uri $etag $body $SessionToken
write-host "  Ende IPv6 Konfiguration" -ForegroundColor Green
write-host "Ende  IP Konfiguration`r`n" -ForegroundColor Green

# DNS Config

# Start DNS 1
dumpdata -Payload "Start Konfiguration DNS Dienste" -Ziel $logtarget
write-host "`r`nStart Konfiguration DNS Dienste" -ForegroundColor Green
write-host "`r`nBaseURl ist:" $RedfishBaseURL
write-host "`r`nRF Session URL ist:" $RedfishSessionURL

$Uri = $RedfishBaseURL+$irmcDNSBaseURL

write-host "`r`nBeginne Enumerierung der Redfish-Endpoints" 
write-host "***********************************************`r`n"

$dnsconfigresponse = redfishendpointread $Uri $SessionToken

write-host "`r`nPatche DNS Server`r`n"
$Uri = $RedfishBaseURL+$irmcDNSBaseUrl
# write-host "Redfish Endpoint ist: $Uri"
$etag = $dnsconfigresponse|select -ExpandProperty "@odata.etag"
   
$body = @{"UseDhcp" = 'false';
        "Domain" = 'irmc.rz.justiz.nrw.de';
        "Timeout" = '2'}

## ToDo: Warum nach  "Domain" = 'irmc.rz.justiz.nrw.de'; ggf. Obtain DHCC ausgegraut?

$data = @{"NameExtension" =' ';
        "AddExtension"='false';
        "AddSerialNumber" = 'false';
        "IrmcName" = $irmcname;
        "UseIrmcNameInsteadOfHostName"='true';
        "RegisterDNS" = 'DnsUpdateEnabled';
        }
$body.Add("DnsName",$data)
patchredfish $Uri $etag $body $SessionToken
### 29.09.: Action ChangeDNSRecord hier einbauen? Hängt ggf. von Berechtigungen zu dyn. Update ab.
write-host "Ende Konfiguration DNS Dienste`r`n" -ForegroundColor Green
# End DNS 1

# Start DNS 2
dumpdata -Payload "Start Konfiguration DNS Server Einträge" -Ziel $logtarget
write-host "Start Konfiguration DNS Server Einträge`r`n" -ForegroundColor Green
write-host "BaseURl ist:" $RedfishBaseURL
write-host "RF Session URL ist:" $RedfishSessionURL

$Uri = $RedfishBaseURL+$irmcDNSServerURL

write-host "Uri für DNS Server IP ist $Uri"
# Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Dns/DnsServers
write-Host "Starte Enumerierung des Endpoints f. DNS Server`r`n"
# To Do Try catch
$dnsserverresponse = redfishendpointread $Uri $SessionToken
$dnsserverresponse
$etag = $dnsserverresponse|select -ExpandProperty "@odata.etag"
Write-Host "Etag des Endpoint $Uri ist $etag`r`n"


# To-Do Weitere Saubere Enumerierung der Endpoints über die Response aus dem obigen GET, s. Redfish4 und 5
# Hier jetzt zunächst: Unter der Annahme, dass die Endpoints passen, Patch der Einträge

If ($sitecode -eq "RZMS"){
    for ($i = 0 ;$i -lt 3; $i++){ 
    $EndUri = $Uri+$i
    $etag = Invoke-RestMethod -Uri $EndUri  -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}|select -ExpandProperty "@odata.etag"
    write-host "DNS Server etag ist $etag`r`n"
    $body = @{"Ip" = $RZMSDNSIP[$i]} 
    
    patchredfish $EndUri $etag $body $SessionToken
    }
}elseif ($sitecode -eq "RZD"){
    for ($i = 0 ;$i -lt 3; $i++){ 
    $EndUri = $Uri+$i
    $etag = Invoke-RestMethod -Uri $EndUri  -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}|select -ExpandProperty "@odata.etag"
    write-host "DNS Server etag ist $etag`r`n"
    $body = @{"Ip" = $RZDDNSIP[$i]} 
    
    patchredfish $EndUri $etag $body $SessionToken
    }
}     

write-host "Ende Konfiguration DNS-Server Einträge`r`n" -ForegroundColor Green    
# End DNS 2
# End DNS

# Start iRMC NTP Konfig
dumpdata -Payload "Start Konfiguration NTP" -Ziel $logtarget
write-host "Start Konfiguration NTP`r`n" -ForegroundColor Green
# $irmcNTPURL = "Managers/iRMC/Oem/ts_fujitsu/iRMCConfiguration/Time"
$Uri = $RedfishBaseURL+$irmcNTPBaseURL
$ntpconfigresponse = redfishendpointread $Uri $SessionToken
$ntpconfigresponse
# $ntpconfigresponse|Get-Member
$RtcMode = $ntpconfigresponse|select -ExpandProperty RtcMode
$etag = $ntpconfigresponse|select -ExpandProperty "@odata.etag"
$body = @{"SyncSource" = 'NTP'}
patchredfish $Uri $etag $body $SessionToken
# redfishendpointread $Uri $SessionToken

$Uri = $RedfishBaseURL+$irmcNTPServerURL
$Uri

if ($sitecode -eq "RZMS"){
    for ($i = 0 ;$i -lt 2; $i++){ 
        $EndUri = $Uri+$i
        $EndUri
        $etag = Invoke-RestMethod -Uri $EndUri  -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}|select -ExpandProperty "@odata.etag"
        write-host "NTP Server etag ist $etag"
        $body = @{"NtpServerName" = $RZMSNTPIP[$i]} 
    
        patchredfish $EndUri $etag $body $SessionToken
    }
}elseif ($sitecode -eq "RZD"){
    for ($i = 0 ;$i -lt 2; $i++){ 
        $EndUri = $Uri+$i
        $EndUri
        $etag = Invoke-RestMethod -Uri $EndUri  -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}|select -ExpandProperty "@odata.etag"
        write-host "NTP Server etag ist $etag"
        $body = @{"NtpServerName" = $RZDNTPIP[$i]} 
    
        patchredfish $EndUri $etag $body $SessionToken
    }
}
     
# redfishendpointread $Uri $SessionToken
write-host "Ende NTP Konfiguration`r`n" -ForegroundColor Green
# Ende iRMC NTP Konfig

# Start Konfig AVR
dumpdata -Payload "Start Konfiguration AVR" -Ziel $logtarget
write-host "Start Konfiguration AVR`r`n" -ForegroundColor Green
$Uri = $RedfishBaseURL+$irmcAVRURL
$avresponse = redfishendpointread $Uri $SessionToken
$avresponse
$etag = $avresponse|select -ExpandProperty "@odata.etag"
$viewer = "H5Viewer"
$body = @{"KVMRedirType" = $viewer} # Nutzung einer Variablen im Body funktioniert
patchredfish $Uri $etag $body $SessionToken
# redfishendpointread $Uri $SessionToken
write-host "Ende Konfig AVR`r`n" -ForegroundColor Green
# Ende Konfig AVR

# Start Konfig WebUI
dumpdata -Payload "Start Konfiguration WebUI" -Ziel $logtarget
write-host "Start Konfiguration WebUI`r`n" -ForegroundColor Green
$Uri = $RedfishBaseURL+$irmcWebUIURL
$webuiresponse = redfishendpointread $Uri $SessionToken
$webuiresponse
$etag = $webuiresponse|select -ExpandProperty "@odata.etag"
$body = @{"DefaultLanguage" = 'De'}
patchredfish $Uri $etag $body $SessionToken
# redfishendpointread $Uri $SessionToken
write-host "Ende Konfig WebUI`r`n" -ForegroundColor Green
# Ende Konfig WebUI

# Start Konfig HPSim
dumpdata -Payload "Start Konfiguration HPSim" -Ziel $logtarget
write-host "Start Konfiguration HPSim`r`n" -ForegroundColor Green
$Uri = $RedfishBaseURL+$irmcServerManagementURL
$hpsimresponse = redfishendpointread $Uri $SessionToken
$hpsimresponse
$etag = $hpsimresponse|select -ExpandProperty "@odata.etag"
$body = @{}
$data = @{"IntegrationEnabled"="false"}
$body.Add("HPSim",$data)
patchredfish $Uri $etag $body $SessionToken
# redfishendpointread $Uri $SessionToken
write-host "Ende Konfig HPSim`r`n" -ForegroundColor Green
# Ende Konfig HPSim

# Start Konfig NetworkService
dumpdata -Payload "Start Konfiguration NetworkServices" -Ziel $logtarget
write-host "Start Konfiguration NetworkServices`r`n" -ForegroundColor Green
$Uri = $RedfishBaseURL+$irmcNetworkServiceURL
$networkservicesresponse = redfishendpointread $Uri $SessionToken
$networkservicesresponse
$etag = $networkservicesresponse|select -ExpandProperty "@odata.etag"

$body = @{}

$data1 = @{
        "TrapCommunityName"='AdminIT';
        "ServicePort" = '161'
        "Enabled"='true';
        "CommunityName" = 'AdminIT';
         }
$body.Add("Snmp",$data1)

$data2 = @{
        "TLS11Enabled"='false';
        "TLS12Enabled" = 'true';
        }
$body.Add("Tls",$data2)

patchredfish $Uri $etag $body $SessionToken

$EndUri = $Uri+"TrapDestinations/0"
$snmptrapresponse = redfishendpointread $EndUri $SessionToken
$snmptrapresponse
$etag = Invoke-RestMethod -Uri $EndUri  -Method Get -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}|select -ExpandProperty "@odata.etag"
write-host "Trap destination etag ist $etag`r`n"
$body = @{"TrapDestinationName" = 'SRZMS090004.justiz.nrw.de'} 
    
patchredfish $EndUri $etag $body $SessionToken
write-host "Ende Konfig NetworkServices`r`n" -ForegroundColor Green
# Ende Konfig NetworkService

# Start Konfig Asset Tag
dumpdata -Payload "Start Konfiguration AssetTag" -Ziel $logtarget
write-host "Start Konfiguration AssetTag`r`n" -ForegroundColor Green
$Uri = $RedfishBaseURL+$irmcSystemURL
$assettagresponse = redfishendpointread $Uri $SessionToken
$assettagresponse
$etag = $assettagresponse|select -ExpandProperty "@odata.etag"
$etag
$body = @{"AssetTag" = $irmcassettag} 
patchredfish $Uri $etag $body $SessionToken
write-host "Ende Konfig Asset Tag`r`n" -ForegroundColor Green
# Ende Konfig Asset Tag

dumpdata -Payload "Server $irmcName über IP $actualip erreichbar" -Ziel $logtarget
write-host "Bitte beachten: Durch die Wartezeit bis zur Aktualisierung der DNS Einträge ist der Server $irmcName zunächt wahrscheinlich nur über seine IP $actualip erreichbar!`r`n" -BackgroundColor White -ForegroundColor DarkRed

#$condition = Read-Host -Prompt 'Session abmelden? Jj/Nn'
        #If ($condition -eq "J" -Or $condition -eq "j"){
            Invoke-RestMethod -Uri $SessionID  -Method Delete -UseBasicParsing -ContentType 'application/json' -Headers @{"Accept"="application/json"; "X-Auth-Token" = $SessionToken}

            #}

# Alle Werte der im Script benutzten Variablen löschen - clever!
Remove-Variable * -ErrorAction SilentlyContinue

