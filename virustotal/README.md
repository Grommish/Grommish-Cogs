For RedBot-Discord Python 3.x

This Cog submits IP and URLs to VirusTotal for scanning when they are sent to a Discord Server.  Malicious or Suspicious results are handled by the Cog.

![image](https://github.com/user-attachments/assets/a1e45f8d-19d2-467f-a53b-53324e448f82)



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
- `[p]vt set dmuser` - Toggle whether a DM is sent to the user (`Default: True`)
- `[p]vt set exclude <@roles>` - Exclude specified roles from link action. Multiple roles accepted
    - Note: While links from excluded roles will not be deleted, they will still be checked at treated as `warn` (DM to User, Reports, etc)
- `[p]vt set modlog <#channel>` - Set modlog channel for recording actions taken (`Default: None`) 
- `[p]vt set punishment <action> [<@punish_role> <#punish_channel>]` Set punishment for sending malicious links.
    Select from `warn`, `ban`, `punish`.
  - `warn` informs the user via DM, and alerts the reports channel.
  - `ban` executes a standard ban.
  - When `punish` is selected, you have to enter the `<@Role>` and `<#TextChannel>` you setup as a Jail. (`Default: Warn`)
- `[p]vt set reportschannel <#reportschannel>` - Set the channel where reports will be sent.
- `[p]vt set threshold <number>` - Set the threshold for number of engines that return positive before taking action (`Default: 5`)

`[p]vt status` - Show the current Cog configuration

![image](https://github.com/user-attachments/assets/fe81ca8c-035f-41fb-b3dc-f4a954e49c19)
![image](https://github.com/user-attachments/assets/945023df-7987-44bc-8c7d-ee7afcf0dce7)


