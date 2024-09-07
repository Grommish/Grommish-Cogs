# virustotal.py
#
# Copyright 2024 - Donald Hoskins <grommish@gmail.com>
# Released under GNU General Public License v3.0
# TODO: Check out AbuseIPDB
#
# A check of the system can be run by using either of the two following URLs/IPs:
# I cannot vouch for the SAFETY of the below links!  DO NOT ACTIVELY GOTO THEM.
#
# http://malware.wicar.org/data/java_jre17_exec.html <- This returns Malicious
# 146.59.228.105 <- This returns Malicious AND Suspicious

from redbot.core import commands, Config, checks, modlog
import aiohttp
import discord
import requests
import datetime
import logging
import base64 # Used by API to encode URL for submission
import re
import urllib.parse
import uuid

log = logging.getLogger("red.VirusTotal")

class VirusTotal(commands.Cog):
    """Check links for malicious content using VirusTotal."""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=736848614378176543, force_registration=True)
        default_guild_settings = {
            "enabled": False,
            "api_key": None,
            "excluded_roles": [],
            "report_channel": None,
            "punishment_action": "Warn",
            "punishment_role": None,
            "punishment_channel": None,
            "threshold": 5,
            "debug": False,
            "dmuser": True,
            "modlog_channel": None,
        }
        self.config.register_guild(**default_guild_settings)
        log.info("VirusTotal link scanning has started.")

    @commands.group(aliases=["vt"])
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal(self, ctx):
        """Manage VirusTotal link checking."""
        pass

    @virustotal.command(name="enable")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_toggle(self, ctx):
        """Toggle link checking."""
        enabled = await self.config.guild(ctx.guild).enabled()
        api = await self.config.guild(ctx.guild).api_key()

        if not api:
            await ctx.send("VirusTotal API Missing.  Use `[p]virustotal set api <api_key>` to set")
            return

        await self.config.guild(ctx.guild).enabled.set(not enabled)
        await ctx.send(f"VirusTotal link checking is now {'enabled' if not enabled else 'disabled'}.")

    @virustotal.command(name="reset")
    @checks.admin_or_permissions(manage_guild=True)
    async def reset_settings(self, ctx):
        """Reset VirusTotal settings to default."""
        await self.config.guild(ctx.guild).clear()
        await ctx.send("VirusTotal settings have been reset to default.")

    @virustotal.command(name="status")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_status(self, ctx):
        """Show the current status of VirusTotal settings."""
        guild = ctx.guild
        embed = await self.get_status(guild)
        await ctx.send(embed=embed)

    @virustotal.group(name="set")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_setgroup(self, ctx):
        """Set various configurations for VirusTotal."""

    @virustotal_setgroup.command(name="api")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_setapi(self, ctx, apikey: str):
        """Set Your VirusTotal API"""
        if not re.match(r'^[a-zA-Z0-9]{64}$', apikey):  # API keys are 64-character alphanumeric
            await ctx.send("Invalid API key format.")
            return
        await self.config.guild(ctx.guild).api_key.set(apikey)
        await ctx.send(f"VirusTotal API has been set.")

    @virustotal_setgroup.command(name="debug")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_debug(self, ctx):
        """Toggle debugging logs."""
        debug = await self.config.guild(ctx.guild).debug()
        await self.config.guild(ctx.guild).debug.set(not debug)
        await ctx.send(f"VirusTotal debug logging is now {'enabled' if not debug else 'disabled'}.")

    @virustotal_setgroup.command(name="dmuser")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_dmuser(self, ctx):
        '''Enable/Disable Sending DM Notifications to the User'''
        dmuser = await self.config.guild(ctx.guild).dmuser()
        await self.config.guild(ctx.guild).dmuser.set(not dmuser)
        await ctx.send(f"VirusTotal {'will' if not dmuser else 'will not'} send a DM to the user when triggered.")

    @virustotal_setgroup.command(name="exclude")
    @checks.admin_or_permissions(manage_guild=True)
    async def exclude_roles(self, ctx, *roles: discord.Role):
        """Exclude specified roles from link checking."""
        guild = ctx.guild
        excluded_roles = await self.config.guild(guild).excluded_roles()

        for role in roles:
            if role.id in excluded_roles:
                # Role already excluded, remove it from the list
                excluded_roles.remove(role.id)
            else:
                # Role not excluded, add it to the list
                excluded_roles.append(role.id)

        await self.config.guild(guild).excluded_roles.set(excluded_roles)

        # Build a formatted string listing the excluded roles
        if excluded_roles:
            excluded_roles_str = "\n".join([f"- {guild.get_role(role_id).name}" for role_id in excluded_roles])
        else:
            excluded_roles_str = "None"
        await ctx.send(f"The following roles have been excluded from VirusTotal link checking:\n{excluded_roles_str}")

    @virustotal_setgroup.command(name="modlog")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_modlog_channel(self, ctx, channel: discord.TextChannel):
        """Set the modlog channel where moderation actions like bans will be logged."""
        await self.config.guild(ctx.guild).modlog_channel.set(channel.id)
        await ctx.send(f"Modlog channel set to: {channel.mention}")

    @virustotal_setgroup.command(name="punishment")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_punishment(self, ctx, action: str, role: discord.Role = None, channel: discord.TextChannel = None):
        """Set punishment for sending malicious links."""
        action_type = action.lower()

        if action_type not in ["warn", "ban", "punish"]:
            return await ctx.send("Invalid action. Please choose 'warn', 'ban', or 'punish'.")

        # Punish action requires both a Role and a TextChannel to send them to.
        if action_type == "punish" and (not role or not channel):
            return await ctx.send("Please specify the role and channel to set for punishment.\r"
                                "Remember! You will NEED to set up the channel to be an appropriate Jail!")

        # Set the Action, Role, and Channel to Config
        await self.config.guild(ctx.guild).punishment_action.set(action_type)
        await self.config.guild(ctx.guild).punishment_role.set(role.id if role else None)
        await self.config.guild(ctx.guild).punishment_channel.set(channel.id if channel else None)

        if action_type == "ban": # Ban them!
            await ctx.send("Senders of malicious links will be banned.")
            await self.config.guild(ctx.guild).punishment_role.set(None)
        elif action_type == "punish": # Punish them!
            await ctx.send(f"Senders of malicious links will be punished with the role: {role.name} and limited to {channel.name}.\r"
                           "Remember! You will NEED to set up the channel to be an appropriate Jail!")
        else: # Defaults to Warn.
            await ctx.send("Senders of malicious links will be informed only.")
            await self.config.guild(ctx.guild).punishment_role.set(None)

    @virustotal_setgroup.command(name="reportschannel")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_reports_channel(self, ctx, channel: discord.TextChannel):
        """Set the channel where reports will be sent."""
        await self.config.guild(ctx.guild).report_channel.set(channel.id)
        await ctx.send(f"Reports channel set to: {channel.mention}")

    @virustotal_setgroup.command(name="threshold")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_threshold(self, ctx, threshold: int):
        """Set the threshold of number of malicious returns before taking action."""
        if threshold <= 0:
            await ctx.send("Please provide a non-negative number value for the threshold.")
            return

        try:
            # Attempt to set the threshold
            await self.config.guild(ctx.guild).threshold.set(threshold)
            await ctx.send(f"VirusTotal threshold set to {threshold} positive returns")
        except ValueError:
            # If the threshold provided is not an integer, notify the user
            await ctx.send("Please provide an number value for the threshold.")

    async def get_status(self, guild):
        """Get the current status of the VirusTotal cog."""
        enabled = await self.config.guild(guild).enabled()
        excluded_roles = await self.config.guild(guild).excluded_roles()
        api_key = await self.config.guild(guild).api_key()
        punishment = await self.config.guild(guild).punishment_action()
        punishment_role_id = await self.config.guild(guild).punishment_role()
        punishment_role = guild.get_role(punishment_role_id) if punishment_role_id else None
        punishment_channel_id = await self.config.guild(guild).punishment_channel()
        punishment_channel = guild.get_channel(punishment_channel_id) if punishment_channel_id else None
        report_channel_id = await self.config.guild(guild).report_channel()
        report_channel = guild.get_channel(report_channel_id) if report_channel_id else None
        report_channel_name = report_channel.name if report_channel else "Not set"
        modlog_channel_id = await self.config.guild(guild).modlog_channel()  # New modlog channel configuration
        modlog_channel = guild.get_channel(modlog_channel_id) if modlog_channel_id else None  # Get modlog channel
        modlog_channel_name = modlog_channel.name if modlog_channel else "Not set"  # Determine modlog channel name
        threshold = await self.config.guild(guild).threshold()
        debug = await self.config.guild(guild).debug()
        dmuser = await self.config.guild(guild).dmuser()

        embed = discord.Embed(title="VirusTotal Status", color=discord.Color.blue())
        embed.add_field(name="Link checking", value="✅ Enabled" if enabled else "❌ Disabled", inline=False)
        embed.add_field(name="VirusTotal API key", value="✅ Set" if api_key else "❌ Not set", inline=False)
        if punishment_role:
            embed.add_field(name="Action upon detection",
                            value = f"Punish them to `{punishment_role.name}` in `{punishment_channel.name}`\n",
                            inline=False)
        else:
            embed.add_field(name="Action upon detection",
                            value=f"{'Warn' if punishment == 'warn' else 'Ban'}",
                            inline=False)
        embed.add_field(name="Reports channel", value=report_channel_name, inline=False)
        embed.add_field(name="Modlog channel", value=modlog_channel_name, inline=False)
        embed.add_field(name="Threshold", value=str(threshold) + ' virus scanning vendors', inline=False)
        embed.add_field(name="Debug Logging", value="✅ Enabled" if debug else "❌ Disabled", inline=False)
        embed.add_field(name="DM User", value="✅ Enabled" if dmuser else "❌ Disabled", inline=False)

        if excluded_roles:
            excluded_roles_names = ", ".join([guild.get_role(role_id).name for role_id in excluded_roles])
            embed.add_field(name="Excluded roles from link checking", value=excluded_roles_names, inline=False)
        else:
            embed.add_field(name="Excluded roles from link checking", value="None", inline=False)

        return embed

    async def check_link(self, message):
        # Check the links asyncroniously
        author = message.author
        content = message.content

        # Somehow got into on_message without being part of a/the guild
        if not hasattr(author, "guild") or not author.guild:
            return

        # Set the guild the message arrived under
        guild = author.guild

        enabled = await self.config.guild(guild).enabled()
        if not enabled:
            return

        debug = await self.config.guild(guild).debug()
        if debug == True:
            log.info(f"[DEBUG] Debug is {'Enabled' if debug else 'Disabled'}")

        api_key = await self.config.guild(guild).api_key()

        # Find all URLs, IPv4, and IPv6 addresses using regular expressions.  These begin with http:// or https:// only
        # Modify the regular expression to match FQDNs only
        urls = re.findall(r'https?://(?:[-\w]+\.)+[a-zA-Z]{2,}(?:/[-\w]+)*\.\w+', content)
        ipv4_addresses = re.findall(r'(?:https?://(?:\d{1,3}\.){3}\d{1,3})', content)
        ipv6_addresses = re.findall(r'(?:https?://)?(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', content)

        # Dedupe
        urls = list(set(urls))
        ipv4_addresses = list(set(ipv4_addresses))
        ipv6_addresses = list(set(ipv6_addresses))

        # Merge all addresses and URLs
        all_addresses = urls + ipv4_addresses + ipv6_addresses

        # If we found Addresses or IPs, check them async
        if all_addresses:
            await self.check_links_task(message, all_addresses)

    async def send_dm_to_user(self, member, embed):
        dmuser = await self.config.guild(member.guild).dmuser()

        # Is sending to DMs to user enabled?
        if not dmuser:
            return
        else:
            try:
                await member.send(embed=embed)
            except discord.errors.Forbidden:
                log.warning("You do not have permissions to send a direct message to the user.")
            except discord.errors.HTTPException:
                log.warning("Sending a direct message to the user failed.")

    async def send_to_reports_channel(self, guild, embed):
        reports_channel_id = await self.config.guild(guild).report_channel()
        reports_channel = guild.get_channel(reports_channel_id)

        if reports_channel:
            try:
                await reports_channel.send(embed=embed)
            except discord.errors.Forbidden:
                log.warning("You do not have permissions to send messages to the reports channel.")
            except discord.errors.HTTPException:
                log.warning("Sending a message to the reports channel failed.")

    async def determine_mal_sus(self, num_malicious, num_suspicious, total_scanners):

        # Format the Title
        if num_malicious >= 1: # Malicious Link
            mal_sus = "Malicious "
            if num_suspicious >= 1:
                mal_sus += "and Suspicious "
        elif num_suspicious >= 1:
            mal_sus = "Suspicious "

        mal_sus += "Link Found"

        # Format the Description
        if num_malicious >= 1: # Malicious Link
            message_content = f"Found Malicious by: {num_malicious} of {total_scanners} virus scanners"
            if num_suspicious >= 1:
                message_content += f"\nFound Suspicious by: {num_suspicious} of {total_scanners} virus scanners"
        elif num_suspicious >= 1:
            message_content = f"Found Suspicious by: {num_suspicious} of {total_scanners} virus scanners"

        # Send back the results
        return mal_sus, message_content # Title and Description

    async def check_links_task(self, message, all_addresses):
        """Async Task for Link checking"""
        author = message.author
        guild = author.guild
        debug = await self.config.guild(guild).debug()
        threshold = await self.config.guild(guild).threshold()
        content = message.content

        # Load up the API key
        api_key = await self.config.guild(guild).api_key()

        if debug:
            log.info(f"[DEBUG] All Addresses: {all_addresses}")
        for address in all_addresses:
            if debug:
                log.info(f"[DEBUG] Found address: {address}")

            headers = {
                "x-apikey": api_key
            }

            # Pull out the URL into its parts and grab just the hostname
            parsed_address = urllib.parse.urlparse(address)
            host_address = parsed_address.hostname

            if debug:
                log.info(f"[DEBUG] HOST ADDRESS: {host_address}")

            # Check if the address is an IPv4 or IPv6 address
            if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', host_address):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{host_address}"
                scan_type = "ip"
            else:
                url = f"https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(address.encode()).decode().strip('=')}"
                scan_type = "url"

            response = requests.get(url, headers=headers)

            if debug:
                log.info(f"[DEBUG] ENCODED ID: {base64.urlsafe_b64encode(address.encode()).decode().strip('=')}")
                log.info(f"[DEBUG] RESPONSE: {response}")


            if response.status_code == 200:
                json_response = response.json()
                json_data = json_response.get("data", {})
                json_attributes = json_data.get("attributes", {})
                json_last_analysis_stats = json_attributes.get("last_analysis_stats", {})

                if scan_type == "ip":
                    link = str(json_response["data"]["id"])
                else:
                    link = json_response["data"]["attributes"]["url"]

                #malicious = json_last_analysis_stats.get("malicious", 0)
                #suspicious = json_last_analysis_stats.get("suspicious", 0)

                total_scanners = json_response["data"]["attributes"]["last_analysis_results"]

                # Count the total number of vendors, ignoring Quttera
                total_scanners_count = len([engine for engine in total_scanners if engine != "Quttera"])

                # Extract the names of the engines that returned malicious or suspicious results, ignoring Quttera
                malicious_engines = []
                suspicious_engines = []

                for engine, result in total_scanners.items():
                    if engine == "Quttera":
                        continue
                    if result['category'] == 'malicious':
                        malicious_engines.append(engine)
                    elif result['category'] == 'suspicious':
                        suspicious_engines.append(engine)

                malicious = len(malicious_engines)
                suspicious = len(suspicious_engines)
                if malicious >= 1 or suspicious > threshold:
                    await self.handle_bad_link(guild, message, malicious, suspicious, total_scanners_count, link, malicious_engines, suspicious_engines)

                if debug:
                    log.info(f"[DEBUG] MALICIOUS: {malicious}")
                    log.info(f"[DEBUG] SUSPICIOUS: {suspicious}")
                    log.info(f"[DEBUG] MALICIOUS ENGINES: {malicious_engines}")
                    log.info(f"[DEBUG] SUSPICIOUS ENGINES: {suspicious_engines}")

    async def handle_bad_link(self, guild, message, num_malicious: int, num_suspicious: int, total_scanners: int, link, malicious_engines: list, suspicious_engines: list):
        member = message.author
        debug = await self.config.guild(guild).debug()

        # Excluded Role IDs
        excluded_roles = await self.config.guild(message.guild).excluded_roles()
        punishment = await self.config.guild(message.guild).punishment_action()
        punishment_channel_id = await self.config.guild(message.guild).punishment_channel()
        punishment_channel = guild.get_channel(int(punishment_channel_id)) if punishment_channel_id else None

        if debug:
            log.info(f"[DEBUG] PUNISH: {punishment}")

        # Build out Embed Title and Description
        title, description = await self.determine_mal_sus(num_malicious, num_suspicious, total_scanners)

        # Build engine details
        malicious_engines_str = ', '.join(malicious_engines) if malicious_engines else 'None'
        suspicious_engines_str = ', '.join(suspicious_engines) if suspicious_engines else 'None'
        member_info = f"{member.name} ({member.id})"

        # Create the embed
        embed = discord.Embed(title=title, description=description, color=discord.Color.red())
        embed.add_field(name="User", value=member_info, inline=False)
        embed.add_field(name="Link", value=link, inline=False)
        embed.add_field(name="Malicious Engines", value=malicious_engines_str, inline=False)
        embed.add_field(name="Suspicious Engines", value=suspicious_engines_str, inline=False)
        embed.set_footer(text=f"Total Scanners: {total_scanners}")

        # The Link is Malicious
        if num_malicious >= 1:
            if punishment == "ban":  # Ban the Sender
                try:
                    # Log the ban to the modlog using the Modlog cog API
                    await modlog.create_case(
                        self.bot,
                        guild,
                        message.created_at,
                        user=member,
                        moderator=guild.me,
                        reason="Malicious link detected",
                        action_type="ban"
                    )

                    log.info(f"Modlog case created for banning user {member} due to malicious link.")
                except RuntimeError:  # modlog channel isn't set
                    pass
                except discord.Forbidden:
                    log.info(
                        "Modlog failed to edit the Discord message for"
                        " the case #%s from guild with ID due to missing permissions."
                    )
                except Exception:
                    log.exception(
                        "Modlog failed to send the Discord message for"
                        " the case #%s from guild with ID %s due to unexpected error."
                    )

                try:
                    await message.guild.ban(member, reason="Malicious link detected")
                except discord.errors.Forbidden:
                    log.error("Bot does not have proper permissions to ban the user")

            elif punishment == "punish":  # This is when it's set to Punish
                embed.add_field(
                    name="Alert!",
                    value=f"You have sent a link that is considered malicious and have been disabled from sending further messages.\n"
                        f"You can appeal this status in `{punishment_channel.name}` channel.",
                    inline=False
                )

                # Modlog - Open the case
                try:
                    log.debug("Entering Punishment Modlog")
                    await modlog.create_case(
                        self.bot,
                        guild,
                        message.created_at,
                        user=member,
                        moderator=guild.me,
                        reason="Malicious link detected",
                        action_type="softban"
                    )
                    
                    log.info(f"Modlog case created for punishing user {member} due to malicious link.")
                except TypeError as e:
                    log.error(f"TypeError while creating a modlog case: {e}")
                except discord.Forbidden as e:
                    log.error(f"Insufficient permissions to create a modlog case: {e}")
                except discord.HTTPException as e:
                    log.error(f"HTTPException occurred while creating a modlog case: {e}")
                except ValueError as e:
                    log.error(f"ValueError while creating a modlog case: {e}")
                except RuntimeError as e:
                    log.error(f"RuntimeError in modlog case creation: {e}")
                except Exception as e:  # Catch-all for any other exceptions
                    log.error(f"An unexpected error occurred while creating a modlog case: {e}")

                # Do the Punishing
                try:
                    # Remove all roles from the user except @everyone
                    roles_to_remove = [role for role in member.roles if role != guild.default_role]
                    await member.remove_roles(*roles_to_remove)
                    
                    # Assign the punishment role
                    punishment_role_id = await self.config.guild(message.guild).punishment_role()
                    if punishment_role_id:
                        punishment_role = message.guild.get_role(punishment_role_id)                        
                        await member.add_roles(punishment_role)

                except discord.errors.Forbidden:
                    log.warning(f"Bot does not have permissions to manage roles for {member.name}.")
                except discord.errors.HTTPException:
                    log.warning(f"Managing roles for {member.name} failed.")

            # Handle the Link in the Message
            try:
                if not any(role.id in excluded_roles for role in member.roles):
                    await message.delete()
            except discord.errors.NotFound:
                log.warning("Message not found or already deleted.")
            except discord.errors.Forbidden:
                log.warning("Bot does not have proper permissions to delete the message")
            except discord.errors.HTTPException:
                log.warning("Deleting the message failed.")

        if debug:
            log.info(f"[DEBUG] Link: {link}")

        # Send to the Reports channel
        await self.send_dm_to_user(member, embed)
        await self.send_to_reports_channel(guild, embed)

    async def log_to_modlog_channel(self, guild, member, reason):
        """Log moderation actions like bans to the configured modlog channel."""
        modlog_channel_id = await self.config.guild(guild).modlog_channel()
        modlog_channel = guild.get_channel(modlog_channel_id)

        if modlog_channel:
            embed = discord.Embed(
                title="User Banned",
                description=f"**User:** {member} ({member.id})\n**Reason:** {reason}",
                color=discord.Color.red(),
                timestamp=datetime.datetime.utcnow(),
            )
            embed.set_footer(text=f"Guild: {guild.name}")
            try:
                await modlog_channel.send(embed=embed)
            except discord.errors.Forbidden:
                log.warning("You do not have permissions to send messages to the modlog channel.")
            except discord.errors.HTTPException:
                log.warning("Sending a message to the modlog channel failed.")
        else:
            log.warning("Modlog channel is not set.")

    @commands.Cog.listener()
    async def on_message(self, message):
        await self.check_link(message)

    @commands.Cog.listener()
    async def on_message_edit(self, before, after):
        await self.check_link(after)

def setup(bot):
    bot.add_cog(VirusTotal(bot))
