#The calling script needs to import these modules:
#Import-Module ActiveDirectory
#Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -EA SilentlyContinue

function Restore-MailboxFolderPermissions
{
<#
.SYNOPSIS
The Restore-MailboxFolderPermissions cmdlet ensures that all of the specified
access control entries are present on mailbox objects sent through the pipeline.

.DESCRIPTION
The Restore-MailboxFolderPermissions cmdlet ensures that all of the specified
access control entries are present on mailbox objects sent through the pipeline.

For each permission that is successfully applied, a result is passed through
the pipeline.

Authored by Nicholas.Waller@unbc.ca in April 2013 for UNBc.

.PARAMETER Entries
Provide a list of access control entries, in the same format as returned from the
Backup-MailboxFolderPermissions cmdlet. This may represent all of the entries for
one mailbox, or for many mailboxes. In either case, only the entries with a guid
that matches the mailbox in the pipeline will be applied.

.EXAMPLE
$aclEntries = Get-Mailbox jsmith | Backup-MailboxFolderPermissions
Get-Mailbox jsmith | Restore-MailboxFolderPermissions -Entries $aclEntries
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param(
	[Parameter(ValueFromPipeline=$True,Mandatory=$True)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Data.Directory.Management.Mailbox]
	$Mailbox,

	# This causes an error if there are zero ACLs to restore, like a non-delegated mailbox
	#[ValidateNotNullOrEmpty()]
	[System.Object[]]
	$Entries
)
begin
{
	# I admit, this might use up a LOT of memory
	# But it's faster and easier to lookup the appropriate ACEs for a given mailbox
	$GroupedEntires = $Entries | Group-Object "MailboxGuid"
}
process
{
	write-host -fore darkgray "restoring for mailbox" $Mailbox.DistinguishedName
	$MailboxGuid = $Mailbox.Guid
	$RelatedEntrySet = $GroupedEntires |
		Where-Object {$_.Name -eq $MailboxGuid}

	if ($RelatedEntrySet -eq $null) {
		Write-Warning "skipping mailbox [$MailboxGuid] (No entries with matching guid)"
		continue
	}
	$RelatedEntries = $RelatedEntrySet |
		Select-Object -ExpandProperty Group

	$UnnneededCount = 0
	foreach ($entry in $RelatedEntries)
	{
		if ($entry.FolderName -eq "GrantSendOnBehalfTo")
		{
			# SendBehalf grant processing occurs at the end of this function
			continue
		}

		$folder = '' + $MailboxGuid + ':' + $entry.FolderName
		$rights = $entry.AccessString.split(";")
		foreach ($right in $rights) {
			# FIXME if the delegated permission has changed, but wasn't removed, then restoring won't fix that.
			$change = Add-MailboxFolderPermission -Identity $folder -User $entry.DelegateSmtp -AccessRights $right -EA SilentlyContinue
			# TODO it would be really nice to have better -whatif support here.
			# Ideally we would only return results for permissions that aren't there already.
			# So users of this function could measure the expected impact before applying.
			if ($change -ne $null)
			{
				New-Object -TypeName PSObject -Property @{
					MailboxGuid=$MailboxGuid;
					FolderName=$entry.FolderName;
					User=$entry.DelegateSmtp;
					AccessRights=$right;
				}
			} else {
				$UnnneededCount++
			}
		}
	}
	if ($UnnneededCount -gt 0) {
		write-host -fore darkGray $UnnneededCount "entries already there, left unchanged"
	}

	# Finally, update the list of delegates who can send on behalf
	[array] $RestoreDelegates = $RelatedEntries |
		Where-Object {$_.FolderName -eq "GrantSendOnBehalfTo"} |
		Select-Object -ExpandProperty 'DelegateUpn' |
		Get-User |
		Select-Object -ExpandProperty 'DistinguishedName'

	if ($RestoreDelegates.count -gt 0) {
		Write-Host -Fore DarkGray "Rebuilding delegates list (I guess it's not necessary, really) == " $RestoreDelegates
		foreach ($delegateDN in $RestoreDelegates)
		{
			Set-Mailbox -Identity $Mailbox -GrantSendOnBehalfTo @{add=$delegateDN} -WarningAction SilentlyContinue
		}
	}

} # End process
} # End function


function Backup-MailboxFolderPermissions
{
<#
.SYNOPSIS
The Backup-MailboxFolderPermissions cmdlet scans mailbox objects for ACLs assigned
to Active Directory users, and compiles them into a list. This list is suitable for
writing to a file, and later reading to restore the permissions.

.DESCRIPTION
The Backup-MailboxFolderPermissions cmdlet scans mailbox objects for ACLs assigned
to Active Directory users, and compiles them into a list.

Authored by Nicholas.Waller@unbc.ca in April 2013 for UNBc.

.PARAMETER Mailbox
Specify a mailbox to scan for permissions, or send multiple mailboxes through the
pipeline to backup permissions for many mailboxes all at once.

.EXAMPLE
Get-Mailbox jsmith | Backup-MailboxFolderPermissions | Export-csv "backup.csv"
More details needed here.
#>

[CmdletBinding()]
param(
	[Parameter(ValueFromPipeline=$True,Mandatory=$True)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Data.Directory.Management.Mailbox]
	$Mailbox
)
process
{
	$FolderNames = $Mailbox |
		Get-MailboxFolderStatistics |
		Select-Object -ExpandProperty FolderPath |
		ForEach-Object { $Mailbox.UserPrincipalName + ":" + $_.Replace("/","\") }	

	$folderTotal = $folderNames.Count
	$folderIndex = 0
	$Activity = "Scanning ACLs for user: " + $mailbox.DisplayName
	foreach ($currentFolderName in $folderNames)
	{
		$folderIndex++
		$statMsg = "Folder: " + $currentFolderName
		$percentDone = $folderIndex / $folderTotal * 100
		Write-Progress -Activity $Activity -Status $statMsg -Percent $percentDone

		$currentFolderName |
			Get-MailboxFolderPermission -ErrorAction SilentlyContinue |
			Where-Object { $_.User.DisplayName -ne "Default" } |
			Where-Object { $_.User.DisplayName -ne "Anonymous" } |
			Where-Object { -not ($_.User.DisplayName.StartsWith("NT User:")) } |
			Foreach-Object {	
				New-Object -TypeName PSObject -Property @{
					MailboxGuid=$Mailbox.Guid.ToString();
					MailboxOwner=$Mailbox.SamAccountName;
					FolderName=$currentFolderName.split(":")[1];
					DelegateUpn=$_.user.ADRecipient.UserPrincipalName;
					DelegateSmtp=$_.User.ADRecipient.PrimarySmtpAddress.ToString();
					AccessString=($_.AccessRights -join ";");
				}

			}
	} # End ForEach
	Write-Progress -Activity $Activity -Status "Done" -Completed

<#
# Don't bother backing up the delegates. That's handled separately in Set-MailboxUser.
# If they aren't backed up they won't be restored, problem solved.
	foreach ($delegate in $Mailbox.GrantSendOnBehalfTo)
	{
		$user = Get-User -Identity $delegate.DistinguishedName
		
		$delegateUpn = $user.UserPrincipalName
		$delegateSmtp = $user.WindowsEmailAddress
		New-Object -TypeName PSObject -Property @{
			MailboxGuid=$Mailbox.Guid;
			MailboxOwner=$Mailbox.SamAccountName;
			FolderName="GrantSendOnBehalfTo";
			DelegateUpn=$delegateUpn;
			DelegateSmtp=$delegateSmtp;
			AccessString="GrantSendOnBehalfTo";
		}
		
	} # End ForEach
#>

} # End process
} # End function


function Disable-MailboxAndWait
{
<#
.SYNOPSIS
The Disable-MailboxAndWait cmdlet works much like the native cmdlet for disabling
mailboxes, except it doesn't return until replication has completed, so you're free
to reconnect the mailbox again immediately.

.DESCRIPTION
The Disable-MailboxAndWait cmdlet works much like the native cmdlet for disabling
mailboxes, except it doesn't return until replication has completed, so you're free
to reconnect the mailbox again immediately.

Also it returns an object that tells you enough about the mailbox to reconnect it.

.PARAMETER Identity
The Identity parameter specifies the mailbox you want to disable.

.EXAMPLE
$unusedMailbox = Disable-MailboxAndWait -Identity (Get-Mailbox "Joe Bloggs")
Connect-Mailbox -Identity $unusedMailbox.Identity -Database $unusedMailbox.Database -User "Joe Bloggs"
#>
[Cmdletbinding(SupportsShouldProcess=$True)]
Param(
	[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Configuration.Tasks.MailboxIdParameter]
	$Identity
)
process
{
	$Mailbox = Get-Mailbox $Identity
	if ($Mailbox -eq $null)
	{
		Write-Error "No mailbox matches identity parameter."
		return
	}

	$upn = $Mailbox.UserPrincipalName

	Write-Host "Will detach mailbox from user" $upn "on" $Mailbox.Database.ToString()
	Disable-Mailbox -Identity $Identity

	# Testing has shown that Get-User executes more quickly than Get-Mailbox or other similar commands - NW
	# Testing has also shown that Get-User and Get-Mailbox are equivalent tests for replication completeness. -NW

	if ($pscmdlet.ShouldProcess("Synchronize-Wait"))
	{
		Write-Host -NoNewline "Waiting for changes to replicate"
		do
		{
			Write-Host -NoNewline '.'
			Start-Sleep -Seconds 1
			$NewUser = Get-User $upn -RecipientTypeDetails UserMailbox -ErrorAction SilentlyContinue
		} while ($NewUser -ne $null)
		Write-Host "Done."
	}

	New-Object -TypeName PSObject -Property @{
		Identity=[String]$Mailbox.LegacyExchangeDn;
		LegacyExchangeDn=[String]$Mailbox.LegacyExchangeDn;
		DisplayName=$Mailbox.DisplayName;
		Database=$Mailbox.Database;
	}
} # End Pipeline Processing
} # End Function


function Connect-MailboxAndWait
{
<#
.SYNOPSIS
The Connect-MailboxAndWait cmdlet works much like the native cmdlet for connecting
mailboxes, except it doesn't return until replication has completed, so it is safe to
immediately begin working with the attached mailbox.

.DESCRIPTION
The Connect-MailboxAndWait cmdlet works much like the native cmdlet for connecting
mailboxes, except it doesn't return until replication has completed, so it is safe to
immediately begin working with the attached mailbox.

.PARAMETER Identity
The Identity parameter specifies the mailbox you want to disable.

.EXAMPLE
$unusedMailbox = Disable-MailboxAndWait -Identity (Get-Mailbox "Joe Bloggs")
Connect-Mailbox -Identity $unusedMailbox.Identity -Database $unusedMailbox.Database -User "Joe Bloggs"
#>
[Cmdletbinding(SupportsShouldProcess=$True)]
Param(
	[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Configuration.Tasks.StoreMailboxIdParameter]
	$Identity,

	[Parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Configuration.Tasks.DatabaseIdParameter]
	$Database,

	[Parameter(Mandatory=$True)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Configuration.Tasks.UserIdParameter]
	$User,

	[String]
	[ValidateNotNullOrEmpty()]
	$Alias
)
process
{

	[Microsoft.Exchange.Data.Directory.Management.User] $UserObj = Get-User $User
	[String] $TargetUpn = $UserObj.UserPrincipalName

	Write-Host "Connecting mailbox to:" $User
	# Redirect Warning IO stream (3>) to null, because this cmdlet specifically addresses that warning
	try {
		if ($Alias -ne '') {
			Connect-Mailbox -Identity $Identity -Database $Database -User $User -Alias $Alias -WarningAction SilentlyContinue
		} else {
			Connect-Mailbox -Identity $Identity -Database $Database -User $User -WarningAction SilentlyContinue
		}
	}
	catch {
		Write-Error "An unknown exception occurred. Maybe the user account is still disabled?"
		return
	}

	# Testing has shown that Get-User executes more quickly than Get-Mailbox or other similar commands - NW
	# Testing has also shown that Get-User and Get-Mailbox are equivalent tests for replication completeness. -NW

	if ($pscmdlet.ShouldProcess("Synchronize-Wait"))
	{
		Write-Host -NoNewline "Waiting for changes to replicate"
		do
		{
			Write-Host -NoNewline '.'
			Start-Sleep -Seconds 1
			if ( ($TargetUpn -eq $null) -or ($TargetUpn -eq '') ) {
				write-error "Can't proceed if UPN is blank"
				return
			}
			$NewUser = Get-User $TargetUpn -RecipientTypeDetails UserMailbox -ErrorAction SilentlyContinue
		} while ($NewUser -eq $null)
		Write-Host "Done."
	}

	$NewUser | Get-Mailbox
} # End Pipeline Processing
} # End Function


function Set-MailboxUser
{
<#
.SYNOPSIS
The Set-MailboxUser transfers ownership of an Exchange Mailbox to a new user in
Active Directory. The mailbox is temporarily disconnected before being connected
to the new user.

.DESCRIPTION
The Set-MailboxUser transfers ownership of an Exchange Mailbox to a new user in
Active Directory. It does this by temporarily disabling the mailbox, then
reconnecting it to the new user.

By default, this cmdlet will attempt to preserve as many permissions and links
as possible, including delegations and access controls. This functionality
can be controlled with the -UpdateDelegates parameter.

Authored by Nicholas.Waller@unbc.ca in April 2013 for UNBc.

.PARAMETER Identity
The mailbox object that will have ownership transferred.

.PARAMETER User
The user who will be receiving ownership of the mailbox.

.PARAMETER UpdateDelegates
By default, the cmdlet will attempt to preserve delegations to and from this
mailbox. If you use the IgnoreLinks switch, no attempt will be made. This will
usually result in complete loss of the "Send On Behalf" public delegates, as
well as SendAs and FullAccess permissions. Furthermore, any mailboxes that had
delegated rights to this mailbox will not be updated, so the ACLs will be
stale and not useful.

.EXAMPLE
Get-Mailbox jsmith@oldcontoso.com | Set-MailboxUser -User jsmith@newcontoso.com

.EXAMPLE
Set-MailboxUser jubloggs -User nobloggs@contoso.com -Confirm:$False
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param(
	[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Configuration.Tasks.MailboxIdParameter]
	$Identity,

	[Parameter(Mandatory=$True,Position=0)]
	[ValidateNotNullOrEmpty()]
	[Microsoft.Exchange.Configuration.Tasks.UserIdParameter]
	$User,

	[bool]
	$UpdateDelegates = $True,

# TODO should allow input of the alias parameter

	[Switch]
	$PassThru
)
begin
{
# Figure out our preferred domain controllers
	[System.Collections.Hashtable] $preferredDC = @{}
	$forest = Get-ADForest
	foreach ($domain in $forest.Domains)
	{
		[Array] $dcs = Get-DomainController -DomainName $domain |
			Select -Last 1
		$preferredDC[$domain] = $dcs[0].DnsHostName
	}
	# TODO is it possible to set this an environment variable or something? do i have to keep it myself?
	# If i have to keep it myself, i must be much more consistent in using it.
	# TODO use more deterministic criteria, like the highest name alphabetically.
}
process
{
	[Microsoft.Exchange.Data.Directory.Management.Mailbox] $Mailbox = Get-Mailbox $Identity
	if ($Mailbox -eq $null)
	{
		Write-error "Can't find mailbox matching: $Identity"
		return
	}

	Try
	{
		[Microsoft.Exchange.Data.Directory.Management.User] $UserObj = Get-User $User
	}
	Catch
	{
		Write-Error "User $User must not be ambiguous. Multiple results were found."
		return
	}
	if ($UserObj -eq $null)
	{
		Write-error "Can't find user matching: $User"
		return
	}

	if ( ($UserObj.UserAccountControl.value__ -band 0x0002) -eq 0x0002 )
	{
		# The second bit in UAC flags means the account is disabled.
		Write-Error "Can't assign mailbox to disabled user account"
		return
	}

	# Shortcut the case where no change is required
	if ($Mailbox.UserPrincipalName -eq $UserObj.UserPrincipalName) {
		If ($PassThru) {
			$Mailbox
		}
		Write-Host -Fore DarkGray "Mailbox $Identity is already assigned to $User."
		return
	}

	# TODO verify that the target user doesn't have a mailbox already!
	# Maybe introduce a -Clobber switch or something similar
	# But that should have a high confirm level
	if ($UserObj.RecipientType -ne "User")
	{
		Write-Error "Target user already has a mailbox."
		return
	}


# First, make copies of the things we want to save.
	[System.Boolean] $UseDatabaseQuotaDefaults = $Mailbox.UseDatabaseQuotaDefaults
	[System.Boolean] $QuotaUnlimited = $Mailbox.ProhibitSendQuota.IsUnlimited
	$QuotaValue = $Mailbox.ProhibitSendQuota
	$QuotaWarning = $Mailbox.IssueWarningQuota

	$PreviousAlias = $Mailbox.Alias

	$EmailAddressPolicyEnabled = $Mailbox.EmailAddressPolicyEnabled

	If ($UpdateDelegates -eq $True) {
		# Get some useful variables, like the old and new domains (can be the same if samName is changing)
		[string] $oldDomain = $Mailbox.Identity.DomainId.ToString()
		[string] $newDomain = $UserObj.Identity.DomainId.ToString()
		[string] $targetUserUpn = $UserObj.UserPrincipalName
	
		# and the list of Users (DN) that we can send on behalf of.
		[Array] $publicDelegatesBL = (Get-ADUser $Mailbox.SamAccountName -Server $preferredDC[$oldDomain] -Properties publicDelegatesBL).publicDelegatesBL
		if ($publicDelegatesBL.count -gt 10) {
			write-warning "More than 10 public delegates? Something must have gone wrong!"
			return
		}
	
		# and the list of email addresses associated with the mailbox
		[Array] $EmailAddresses = $Mailbox.EmailAddresses
	
		# and the DN of the old mailbox, so we can remove it from publicDelegates where it exists
		[String] $oldMailboxDn = $Mailbox.DistinguishedName
			
		# Cleanup any references to this mailbox so they don't become zombies.
	
		# Find all the regular mail users that we're configured to send on behalf of, and remove that permission.
		# If the user has no mailbox, or if they're disabled, they get skipped.
		# write-host "delegatesBL: " $publicDelegatesBL
		[Array] $OtherBoxesWeSendBehalfOf = @()
		$publicDelegatesBL |
			Get-User -RecipientTypeDetails UserMailbox -EA SilentlyContinue |
			Get-Mailbox |
			ForEach-Object {
				$OtherBoxesWeSendBehalfOf += $_
				# TODO note that Outlook freaks out if the delegates change behind the scenes. it really needs to be closed and reopened.
				Write-Host -Fore Cyan $Mailbox.UserPrincipalName " releases permissions to send on behalf of user " $_.UserPrincipalName
				Set-Mailbox -Identity $_.DistinguishedName -GrantSendOnBehalfTo @{remove=$oldMailboxDn}
				Start-Sleep -Seconds 2 # this is scary, slow it down a bit
			}

# Find all the mail-enabled public folders that we're configured to send on behalf of
# We don't have the advantage of a publicDelegatesBL, but we can assume that there is a small number of public folders.
		[Array] $MailPublicFoldersWeSendBehalfOf = Get-MailPublicFolder -WarningAction SilentlyContinue |
			Where-Object {
				foreach ($grant in $_.GrantSendOnBehalfTo)
				{
					if ($grant.DistinguishedName -eq $oldMailboxDn)
					{
						$true
						break
					}
				}
				$false
			} |
			ForEach-Object {
				$_.Identity.ToString()
			}

		write-host "Public folders that delegate SendBehalf to us:" $MailPublicFoldersWeSendBehalfOf

# Also release our SendBehalf permissions on mail-enabled public folders
		foreach ($publicFolderId in $MailPublicFoldersWeSendBehalfOf)
		{
			if ($publicFolderId -eq $null -or $publicFolderId -eq '')
			{
				# TODO fix this is a dirty hack
				continue
			}
			Write-Host -Fore Cyan $Mailbox.UserPrincipalName " releases permissions to send on behalf of public folder " $publicFolderId
			Set-MailPublicFolder -Identity $publicFolderId -GrantSendOnBehalfTo @{remove=$oldMailboxDn}
			Start-Sleep -Seconds 2 # this is scary, slow it down a bit
		}

# FIXME this is duplicate code and needs to be removed, but that reveals a few other problems (code or environment, not sure)
# Also release on sendbehalf permissions on regular user mailboxes
		$publicDelegatesBL |
			Get-User -RecipientTypeDetails UserMailbox -EA SilentlyContinue |
			Get-Mailbox |
			ForEach-Object {
				$OtherBoxesWeSendBehalfOf += $_
				# TODO note that Outlook freaks out if the delegates change behind the scenes. it really needs to be closed and reopened.
				Write-Host -Fore Cyan $Mailbox.UserPrincipalName " releases permissions to send on behalf of " $_.UserPrincipalName
				Set-Mailbox -Identity $_.DistinguishedName -GrantSendOnBehalfTo @{remove=$oldMailboxDn}
				Start-Sleep -Seconds 2 # this is scary, slow it down a bit
			}

# Backup ACLs on all the mailbox subfolders
		$FolderAcls = $OtherBoxesWeSendBehalfOf | Backup-MailboxFolderPermissions

# Take a look at the FullAccess delegates backlist to see what we have access to
		#write-host "searching samname" $Mailbox.SamAccountName
		#write-host "searching server" $preferredDC[($Mailbox.UserPrincipalName.split('@')[1])]
		[String[]] $myFullAccessMailboxesDN = Get-ADUser $Mailbox.SamAccountName -Server $preferredDC[($Mailbox.UserPrincipalName.split('@')[1])] -Properties msExchDelegateListBL |
			Select-Object -ExpandProperty msExchDelegateListBL
		
		write-host "Currently have full access on these other mailboxes:" $myFullAccessMailboxesDN ($myFullAccessMailboxesDN.count)

<#
# Public folder permissions
# FIXME TODO this is pretty slow, perhaps we could do this once during begin{} and build a hash table?
# Supposedly the PublicFolderClientPermissions are associated with a mailbox, not with an AD user, and they don't need to be ported at all.
		Write-Host "Discovering public folder permissions"
		[array] $PublicFolderPermissions = Get-PublicFolder -Recurse "\" | Get-PublicFolderClientPermission -User $Mailbox.UserPrincipalName
#>
	}

# Now actually trigger the mailbox move.

	if ($pscmdlet.ShouldProcess($Identity)) {
		$mbox = Disable-MailboxAndWait -Identity $Identity
		$newMailbox = Connect-MailboxAndWait -Identity $mbox.Identity -Database $mbox.Database -User $User
		$newExchUser = $newMailbox | Get-User
	} else {
		Write-Host "Can't go past here without real changes."
		return
	}

	# After the move, our mailbox and user objects are no longer correct. But still need them so we can
	# strip the fullaccess permissions that were granted to the old username.
	# $Mailbox = $null
	# $UserObj = $null

# Finally, recreate all the permissions that are lost or incorrect.
	$newMailbox | Set-Mailbox -Alias $PreviousAlias
	$newMailbox | set-mailbox -EmailAddressPolicyEnabled $false

	# FIXME this isn't even a perfect workaround, it assumes that either both quotas are unlimited, or neither
	if ($QuotaUnlimited)
	{
		Write-Host "Copying mailbox quota: unlimited"
		$newMailbox | Set-Mailbox -ProhibitSendQuota Unlimited -IssueWarningQuota Unlimited -UseDatabaseQuotaDefaults $UseDatabaseQuotaDefaults
	}
	else
	{
		Write-Host "Copying mailbox quota:" $QuotaValue
		$newMailbox | Set-Mailbox -ProhibitSendQuota $QuotaValue -IssueWarningQuota $QuotaWarning -UseDatabaseQuotaDefaults $UseDatabaseQuotaDefaults
	}


	If ($UpdateDelegates -eq $True) {
# Restore SendBehalf permissions on user mailboxes
		# Find all the users that we're configured to send on behalf of, and recreate that permission.
		# If the user has no mailbox, or if they're disabled, they get skipped.
		# write-host "delegatesBL: " $publicDelegatesBL
		$publicDelegatesBL |
			Get-User -RecipientTypeDetails UserMailbox -EA SilentlyContinue |
			Get-Mailbox |
			ForEach-Object {
				Write-Host -Fore Cyan $newMailbox.UserPrincipalName " claims permissions to send on behalf of user " $_.UserPrincipalName
				Set-Mailbox -Identity $_.DistinguishedName -GrantSendOnBehalfTo @{add=$newMailbox.DistinguishedName}
			}
		# Great, now this user can send on behalf of other users again.
		# TODO but other users still can't send on behalf of this user, oops!
		# FIXME also restore outbound delegations for Send On Behalf
	
		# Disable email address policy? TODO: why? (????)
		# This always throws warnings because it
		Write-Host "Setting Email Address Policy Enabled" $False
		Set-Mailbox -Identity $newMailbox -EmailAddressPolicyEnabled $False -WarningAction SilentlyContinue
	
		# Re-create the list of proxy email addresses
		Write-Host "Restoring list of proxy email addresses"
		Set-Mailbox -Identity $newMailbox -EmailAddresses $EmailAddresses

# Restore ACLs on all the subfolders in mailboxes we can send on behalf of (gimme gimme!)
		if ($FolderAcls.count -gt 0) {
			# For unknown reasons, the mailbox ACL restoration process won't work unless it is slightly delayed.
			# It seems to be related to a problem resolving the mail alias to the old mailbox. 10 seconds seems okay.
			# Nope, 10 seconds is not always enough! :-(
			Write-Host -Fore DarkGray "Waiting 20 seconds before attempting to restore mailbox folder ACLs."
			Start-Sleep -Seconds 20
			$OtherBoxesWeSendBehalfOf | Restore-MailboxFolderPermissions -Entries $FolderAcls
			# As a point of interest, the "NT User" permissions still work correctly, and even return to normal
			# if a user is rolled back. So there's no need to remove NT User permissions in this script.
	
			# More perplexingly, it seems like SOMETIMES the mailbox acl restore isn't needed. It just magically happens?
		}

# Recreate my own full access privileges on other mailboxes
		foreach ($fullAccessMailbox in $myFullAccessMailboxesDN) {
			if ($fullAccessMailbox -eq '' -or $fullAccessMailbox -eq $null) {
				continue
			}
			$targetMbox = get-mailbox $fullAccessMailbox
			$targetMboxDomain = $targetMbox.UserPrincipalName.split('@')[1]

			Write-Host "Modify" $fullAccessMailbox "--> Append" $newExchUser.UserPrincipalName
			$discard = Add-MailboxPermission -Identity $fullAccessMailbox -AccessRights FullAccess -User $newExchUser.UserPrincipalName -DomainController $preferredDC[$targetMboxDomain]
			Write-Host "Modify" $fullAccessMailbox "--> Remove" $Mailbox.UserPrincipalName
			Remove-MailboxPermission -Identity $fullAccessMailbox -AccessRights FullAccess -User $Mailbox.UserPrincipalName -DomainController $preferredDC[$targetMboxDomain]
		}

# Restore SendBehalf permissions on public folders
		# Worryingly, this seems to fail sometimes if we move too quickly. Even once replication has completed.
		# Maybe because public folders are in ADR (forest root), where none of the users are?
		# I think I would need to manually (Get-ADUser) poll the forest root domain, if possible
		if ($MailPublicFoldersWeSendBehalfOf.count -gt 0)
		{
			# write-host "Apparently we need to wait just a little bit longer, in order to manipulate public folders. (40s)"
			# But how long, really?
			# Start-Sleep -Seconds 40
		}
		foreach ($publicFolderId in $MailPublicFoldersWeSendBehalfOf)
		{
			if ($publicFolderId -eq $null -or $publicFolderId -eq '')
			{
				# TODO this is a dirty hack
				continue
			}
			Write-Host -Fore Cyan $newMailbox.UserPrincipalName " claims permissions to send on behalf of public folder " $publicFolderId
			#Set-MailPublicFolder -Identity $publicFolderId -GrantSendOnBehalfTo @{add=$newMailbox.DistinguishedName}
			# TODO: investigate There seems to be some problem using Set-MailPublicFolder to add permissions
			# so I'll connect directly to the domain controller with LDAP instead
			# and that will propagate back into Exchange after a while

			$publicFolderDn = Get-MailPublicFolder $publicFolderId |
				Select-Object -expandProperty DistinguishedName

			# FIXME don't hardcode this DC for the forest root domain
			Get-ADObject -Filter {objectClass -eq 'publicFolder'} -SearchBase $publicFolderDn -server pg-adr-dc-04 |
				Set-AdObject -add @{publicDelegates=@($newExchUser.DistinguishedName)}
		}


<#
# Supposedly the PublicFolderClientPermissions are associated with a mailbox, not with an AD user, and they don't need to be ported at all.
# Recreate public folder permissions for new account
		Write-Host "Restoring public folder permissions"
		if ($PublicFolderPermissions -ne $null -and $PublicFolderPermissions.count -gt 0)
		{
			foreach ($pubf in $PublicFolderPermissions)
			{
				Add-PublicFolderClientPermission -Identity $pubf.identity -User $newExchUser.UserPrincipalName -AccessRights $pubf.accessrights -Confirm:$False
			}
		}
#>

	}

	if ($PassThru)
	{
		$newMailbox
	}
} # End process
end
{
	# TODO discover this dynamically, only apply if needed
	# Get-MailboxDatabase -Server pg-adr-exch-12 | Clean-MailboxDatabase

	# TODO discover this dynamically, only apply if needed
	# Update-GlobalAddressList -Identity "Default Global Address List"
}
} # End function
