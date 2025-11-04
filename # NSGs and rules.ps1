# NSGs and rules
$nsgs = Get-AzNetworkSecurityGroup
foreach ($nsg in $nsgs) {
    foreach ($rule in $nsg.SecurityRules) {
        $results += [PSCustomObject]@{
            Subscription       = $sub.Name
            ResourceType       = "NSG Rule"
            NSGName            = $nsg.Name
            RuleName           = $rule.Name
            Direction          = $rule.Direction
            Access             = $rule.Access
            Priority           = $rule.Priority
            Source             = $rule.SourceAddressPrefix
            Destination        = $rule.DestinationAddressPrefix
            Port               = $rule.DestinationPortRange
            Protocol           = $rule.Protocol
        }
    }
}

# Route Tables (UDRs)
$routes = Get-AzRouteTable
foreach ($routeTable in $routes) {
    foreach ($route in $routeTable.Routes) {
        $results += [PSCustomObject]@{
            Subscription       = $sub.Name
            ResourceType       = "Route"
            Name               = $routeTable.Name
            AddressPrefix      = $route.AddressPrefix
            NextHopType        = $route.NextHopType
            NextHopIpAddress   = $route.NextHopIpAddress
        }
    }
}

# Public IPs
$publicIPs = Get-AzPublicIpAddress
foreach ($ip in $publicIPs) {
    $results += [PSCustomObject]@{
        Subscription       = $sub.Name
        ResourceType       = "Public IP"
        Name               = $ip.Name
        IPAddress          = $ip.IpAddress
        AssignedTo         = $ip.IpConfiguration.Id
        AllocationMethod   = $ip.PublicIpAllocationMethod
        SKU                = $ip.Sku.Name
    }
}

# Export to CSV
$timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$csvPath = "$env:USERPROFILE\Desktop\Azure_NetworkSecurity_Assessment_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nExport complete: $csvPath" -ForegroundColor Green
