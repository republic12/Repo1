$serverList = @();sss
Get-ADComputer -LDAPFilter '(cn=*DC*)' | % { $serverList += $_.DNSHostName; }
Invoke-Command -ComputerName $serverList -ScriptBlock {
$select = @{
    'Username' = 5
    'LogonType' = 10
    'FailureReason' = 8
    'LogonProcessName' = 11
    'AuthenticationPackageName' = 12
    'WorkstationName' = 13
    'TargetDomainName' = 6
    #'ProcessId' = 17
    'ProcessName' = 18
    'IpAddress' = 19


}

$events = get-winevent -FilterHashtable @{'LogName'= 'Security';'Id' = 4625} -MaxEvents 30

$selected_events = ForEach ($event in $events)
{
    $new_event = $event
    ForEach($key in $select.Keys)
    {
        $new_event = $new_event | 
        Select-Object *,@{
            'Name' = $key
            'Expression' = { $_.Properties[$select[$key]].Value }
        }
    }
    $new_event
}

$selected_events | 
Select-Object -Property ([array]'TimeCreated' + [String[]]$select.Keys)} >c:\temp\lockout.log