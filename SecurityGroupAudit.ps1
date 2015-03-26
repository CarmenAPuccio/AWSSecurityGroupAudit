## SecurityGroupAudit by Carmen A. Puccio 4/16/15
## Scans an AWS region and deletes/logs all Security Groups not in use per VPC in that region.
## For reference, here are the region codes to pass to the $region variable.
## US East (N. Virginia) us-east-1
## US West (Oregon) us-west-2
## US West (N. California) us-west-1
## EU (Ireland) eu-west-1
## EU (Frankfurt) eu-central-1
## Asia Pacific (Singapore) ap-southeast-1
## Asia Pacific (Sydney) ap-southeast-2	
## Asia Pacific (Tokyo) ap-northeast-1
## South America (Sao Paulo) sa-east-1

$accessKeyID = "InsertYourAccessKey"
$secretAccessKey = "InsertYourSecretKey"
$region = "us-east-1"
$logfile = "C:\Users\cpuccio\Desktop\SecurityGroupAudit_$(Get-Date -Format `"yyyyMMdd_hhmmss`").txt"

try
{
    # Simple logger function
    function log($string, $color)
    {
        if ($color -eq $null) {$color = "white"}
        write-host $string -ForegroundColor $color
        $string | out-file -FilePath $logfile -Append
    }

    $vpc = Get-EC2Vpc -AccessKey $accessKeyID -Region $region -SecretKey $secretAccessKey
    $rds = Get-RDSDBInstance -AccessKey $accessKeyID -Region $region -SecretKey $secretAccessKey

    # Create a HashTable for all Security Groups in use. This could be EC2 or RDS Security Groups.
    $securityGroupsInUse = @{}
    # Array for Nested Security Group ID's
    $securityGroupsNested = @()
    # Array for Orphaned Security Group ID's
    $securityGroupsOrphaned = @()
    # Array for Security Group's Deleted
    $securityGroupsDeleted = @()

    function Remove-NestedGroupsAndDelete
    {
        param 
        (
            [Parameter(Mandatory=$true)]$obj,
            [Parameter(Mandatory=$true)]$type
        )

        try
        {
            $EC2SecGrpToDel = Get-EC2SecurityGroup -AccessKey $accessKeyID -GroupId $obj -Region $region -SecretKey $secretAccessKey

            if ($type -eq "LiveGroupInbound")
            {           
                foreach ($nest in $EC2SecGrpToDel.IpPermissions)
                {
                        $nestedGrp = $nest | Where-Object ({$_.UserIdGroupPairs.GroupId -in $securityGroupsNested -or $_.UserIdGroupPairs.GroupId -in $securityGroupsOrphaned})
                
                        foreach ($grp in $nestedGrp)
                        {
                            Revoke-EC2SecurityGroupIngress -AccessKey $accessKeyID -GroupId $EC2SecGrpToDel.GroupId -IpPermission $grp -Region $region -SecretKey $secretAccessKey
                        }                
                }
            }

            if ($type -eq "LiveGroupOutbound")
            {
                foreach ($nest in $EC2SecGrpToDel.IpPermissionsEgress)
                {

                    $nestedGrp = $nest | Where-Object ({$_.UserIdGroupPairs.GroupId -in $securityGroupsNested -or $_.UserIdGroupPairs.GroupId -in $securityGroupsOrphaned})
                
                    foreach ($grp in $nestedGrp)
                    {
                        Revoke-EC2SecurityGroupEgress -AccessKey $accessKeyID -GroupId $EC2SecGrpToDel.GroupId -IpPermission $grp -Region $region -SecretKey $secretAccessKey
                    }
                }   
            }

            if ($type -eq "OrphanedGroupInbound")
            {

                foreach ($nest in $EC2SecGrpToDel.IpPermissions)
                {
                    $nestedGrp = $nest | Where-Object {$_.UserIdGroupPairs.GroupId -in $securityGroupsNested}
                
                    foreach ($grp in $nestedGrp)
                    {
                        Revoke-EC2SecurityGroupIngress -AccessKey $accessKeyID -GroupId $EC2SecGrpToDel.GroupId -IpPermission $grp -Region $region -SecretKey $secretAccessKey
                    }
                }            
            }

            if ($type -eq "OrphanedGroupOutbound")
            {
                foreach ($nest in $EC2SecGrpToDel.IpPermissionsEgress)
                {
                    $nestedGrp = $nest | Where-Object {$_.UserIdGroupPairs.GroupId -in $securityGroupsNested}
                
                    foreach ($grp in $nestedGrp)
                    {
                       Revoke-EC2SecurityGroupEgress -AccessKey $accessKeyID -GroupId $EC2SecGrpToDel.GroupId -IpPermission $grp -Region $region -SecretKey $secretAccessKey
                    }
                }            
            }

            if ($type -eq "GroupToDelete")
            {
                log "Trying to delete Security Group: $($EC2SecGrpToDel.GroupId)" Green

                # Can't delete the default Security Group
                if ($EC2SecGrpToDel.GroupName -eq "default")
                {
                    log "Can't delete the default Security Group. Skipping"
                }
                else
                {
                    if ($EC2SecGrpToDel.GroupId -notin $securityGroupsDeleted)
                    {
                        Remove-EC2SecurityGroup -AccessKey $accessKeyID -GroupId $EC2SecGrpToDel.GroupId -Region $region -SecretKey $secretAccessKey
                        log "Security Group: $($EC2SecGrpToDel.GroupId) removed successfully" Green
                        $securityGroupsDeleted += $EC2SecGrpToDel.GroupId
                    }
                }
            }
        }
        
        catch [System.Exception]
        {
            log $_.Exception.ToString() red
        }          
    }

    function Check-securityGroupsInUse-Hash
    {
        param
        (
            [Parameter(Mandatory=$true)]$Key
        )

        if (!$securityGroupsInUse.ContainsKey($Key))
        {
            
                Write-Host -ForegroundColor Yellow "FOUND EC2 SECURITY GROUP IN USE FOR: $id"
                $securityGroupsInUse.add($Key, $allSecurityGroups.Item($Key))
                Write-Host $Key, $allSecurityGroups.Item($Key)

         }      
    }

    # RDS SecurityGroup lookup.
    # I can't find a filter to show a RDS VPC ID so I add the VPCSecurityGroups early on to the hash.
    # The Get-RDSDBInstance call only returns the VpcSecurityGroups ID and not the name from what I see. 
    # Hence the extra call to Get-EC2SecurityGroup. 
    # I'm also skipping the Hash check function above because whatever it finds is not in the Hash since it's everything in that region based off the -active flag.
    foreach ($dbinstance in $rds)
    {
        if ($dbinstance.VpcSecurityGroups.Status -eq 'active')
        {
            Write-Host -ForegroundColor Yellow "FOUND RDS SECURITY GROUPS IN USE"
            $dbsecuritygroup = Get-EC2SecurityGroup -AccessKey $accessKeyID -Region $region -SecretKey $secretAccessKey -GroupId $dbinstance.VpcSecurityGroups.VpcSecurityGroupId
            $securityGroupsInUse.Add($dbsecuritygroup.GroupName, $dbinstance.VpcSecurityGroups.VpcSecurityGroupId)
            $securityGroupsInUse
        }
    }

    # Loop through VPC's in region specified
    foreach ($id in $vpc.VpcId)     
    {
        $ec2VpcFilter = New-Object Amazon.EC2.Model.Filter
        $ec2VpcFilter.Name = 'vpc-id'
        $ec2VpcFilter.Value = $id

        # Create a HashTable to hold all Security Groups for lookups later.
        $allSecurityGroups = @{}
        Write-Host -ForegroundColor Green "ALL EC2 SECURITY GROUPS FOR: $id"
        # Oddly enough, RDS Security Groups come back even though it's an EC2 call below.        
        $ec2SecurityGroups = Get-EC2SecurityGroup -AccessKey $accessKeyID -Region $region -SecretKey $secretAccessKey -Filter $ec2VpcFilter

        foreach ($ec2SecGroup in $ec2SecurityGroups)
        {
            if (!$allSecurityGroups.ContainsKey($ec2SecGroup.GroupName) -and !$allSecurityGroups.ContainsValue($ec2SecGroup.GroupId))
            {
                $allSecurityGroups.add($ec2SecGroup.GroupName, $ec2SecGroup.GroupId)
            }
        }

        $allSecurityGroups
    
        # To see what Security Groups are in use you have to check the EC2 instances.
        $ec2ModelReservation = Get-EC2Instance -AccessKey $accessKeyID -Region $region -SecretKey $secretAccessKey -Filter $ec2VpcFilter

        foreach($reservation in $ec2ModelReservation)
        {
            foreach ($instance in $reservation.Instances)
            {
                # The below split may be more common if there are multiple Security Groups added to one instance. 
                if ($instance.SecurityGroups.GroupName.Length -gt 1)
                {
                    $lists = $instance.SecurityGroups.GroupName.split(",");
                    foreach($l in $lists)
                    {
                        #Write-Host $l
                        #$securityGroupsInUse.ContainsKey($l)
                        Check-securityGroupsInUse-Hash($l)
                    }
                }

                else
                {
                    Check-securityGroupsInUse-Hash($instance.SecurityGroups.GroupName)
                }
            }
        }

        # Final Comparison to see what's in the allSecurityGroups HashTable versus the securityGroupsInUse HashTable.
        # Anything not in securityGroupsInUse is an orphaned group and can be deleted.
        # Before anything can be deleted, all nested references must be removed.
        # Using the logger function here in case we ever need to review what was deleted.
        # Add to securityGroupsNested Array for tracking purposes to clean nested groups first.
        Write-Host -ForegroundColor Red "EC2 SECURITY GROUPS NOT IN USE FOR: $id"
        foreach ($group in $allSecurityGroups.keys)
        {
            if (!$securityGroupsInUse.ContainsKey($group))
            {   
                $securityGroupsOrphaned += $allSecurityGroups.Item($group)
                
                write-host $group $allSecurityGroups.Item($group)
                $orphanedGroups = Get-EC2SecurityGroup -AccessKey $accessKeyID -Region $region -SecretKey $secretAccessKey -GroupId $allSecurityGroups.Item($group)
                foreach ($orphanedGrp in $orphanedGroups)
                {
                    log "--------------------------------------"

                    log "Description Information" Green
                    log "Name: $($orphanedGrp.GroupName)"
                    log "Group ID: $($orphanedGrp.GroupId)"
                    log "Description: $($orphanedGrp.Description)"
                    log "VPC ID: $($orphanedGrp.VpcId)"
                    log "Region: $($region)"

                    log "Tag Information (if any...)" Green
                    foreach ($tag in $orphanedGrp.tag)
                    {
                        log "$($tag.Key) : $($tag.Value)"
                    }

                    log "Inbound Rules:" Green
                        foreach ($inboundRule in $orphanedGrp.IpPermissions)
                        {
                            log "Protocol: $($inboundRule.IpProtocol)"
                            log "Port Range: $($inboundRule.ToPort)"
                            log "Source: $($inboundRule.IpRanges)"
                            log "Source Security Group Reference: $($inboundRule.UserIdGroupPairs.GroupId)"
                            if ($inboundRule.UserIdGroupPairs.GroupId)
                            {
                                foreach ($nest in $inboundRule.UserIdGroupPairs.GroupId)
                                {                                    
                                    $securityGroupsNested += $nest                                    
                                    Remove-NestedGroupsAndDelete $orphanedGrp.GroupId "OrphanedGroupInbound"                                
                                }
                            }                            
                        }

                    log "Outbound Rules:" Green
                        foreach ($outboundRule in $orphanedGrp.IpPermissionsEgress)
                        {
                            log "Protocol: $($outboundRule.IpProtocol)"
                            log "Port Range: $($outboundRule.ToPort)"
                            log "Destination: $($outboundRule.IpRange)"
                            log "Destination Security Group Reference: $($outboundRule.UserIdGroupPairs.GroupId)"
                            if ($outboundRule.UserIdGroupPairs.GroupID)
                            {
                                foreach ($nest in $outboundRule.UserIdGroupPairs.GroupID)
                                {
                                    $securityGroupsNested += $nest
                                    Remove-NestedGroupsAndDelete $orphanedGrp.GroupId "OrphanedGroupOutbound"
                                }  
                            }                            
                        }

                    log "OwnerID: $($orphanedGrp.OwnerId)"                                         
                }
            }
        }

        # Clean up live Security Groups with references to orphaned groups
        foreach ($obj in $securityGroupsInUse.Values)
        {
            Remove-NestedGroupsAndDelete $obj "LiveGroupInbound"
            Remove-NestedGroupsAndDelete $obj "LiveGroupOutbound"
        }

        # Final delete
        foreach ($obj in $allSecurityGroups.keys)
        {
            if (!$securityGroupsInUse.ContainsKey($obj))
            {                
                Remove-NestedGroupsAndDelete $allSecurityGroups.Item($obj) "GroupToDelete"  
            }
        }
    }
}

catch [System.Exception]
{
    log $_.Exception.ToString() red
}