For RedBot-Discord Python 3.x

This Cog submits IP and URLs to VirusTotal for scanning when they are sent to a Discord Server.  Malicious or Suspicious results are handled by the Cog.

Where `[p]` is your Bot's Hotkey.

To Install:

Add the Repo to your RedBot-Discord instance:
`[p]repo add Grommish-Cogs https://github.com/Grommish/Grommish-Cogs.git main`
`[p]cog install Grommish-Cogs virustotal`
`[p]load virustotal`
`[p]virustotal status`

Usage:  `[p]virustotal` / `[p]vt`

`[p]vt enable` - Toggles whether Link Checking is active

`[p]vt reset` - Reset the Configuration to Defaults

`[p]vt set` - Set Configuration Options
- `[p]vt set api <api_key>` - Set Your VirusTotal API
- `[p]vt set debug` - Toggle debugging logs. (`Default: False`)
- `[p]vt set exclude <@roles>` - Exclude specified roles from link checking. Multiple roles accepted
- `[p]vt set punishment <action> [<@punish_role> <#punish_channel>]` Set punishment for sending malicious links. Select from `Warn`, `Ban`, `Punish`.  When `Punish` is selected, you have to enter the `<@Role>` and `<#TextChannel>` you setup as a Jail. (`Default: Warn`)
- `[p]vt set reportschannel <#reportschannel>` - Set the channel where reports will be sent.
- `[p]vt set threshold <number>` - Set the threshold of number of malicious returns before taking action (`Default: 5`)

`[p]vt status` - Show the current Cog configuration
