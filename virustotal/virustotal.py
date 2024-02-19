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

from redbot.core import commands, Config, checks
import aiohttp
import discord
import requests
import datetime
import logging
import base64 # Used by API to encode URL for submission
import re

log = logging.getLogger("VirusTotal")

class VirusTotal(commands.Cog):
    """Check links for malicious content using VirusTotal."""

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890, force_registration=True)
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
        await self.config.guild(ctx.guild).api_key.set(apikey)
        await ctx.send(f"VirusTotal API has been set.")

    @virustotal_setgroup.command(name="debug")
    @checks.admin_or_permissions(manage_guild=True)
    async def virustotal_debug(self, ctx):
        """Toggle debugging logs."""
        debug = await self.config.guild(ctx.guild).debug()
        await self.config.guild(ctx.guild).debug.set(not debug)
        await ctx.send(f"VirusTotal debug logging is now {'enabled' if not debug else 'disabled'}.")

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

    @virustotal_setgroup.command(name="punishment")
    @checks.admin_or_permissions(manage_guild=True)
    async def set_punishment(self, ctx, action: str, role: discord.Role = None, channel: discord.TextChannel = None):
        """Set punishment for sending malicious links."""
        action_type = action.lower()

        if action_type not in ["warn", "ban", "punish"]:
            return await ctx.send("Invalid action. Please choose 'warn', 'ban', or 'punish'.")

        if not channel:
            return await ctx.send("Please specify a valid text channel for punishment.")

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
        if threshold < 0:
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
        threshold = await self.config.guild(guild).threshold()
        debug = await self.config.guild(guild).debug()

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
        embed.add_field(name="Threshold", value=str(threshold) + ' virus scanning vendors', inline=False)
        embed.add_field(name="Debug Logging", value="✅ Enabled" if debug else "❌ Disabled", inline=False)

        if excluded_roles:
            excluded_roles_names = ", ".join([guild.get_role(role_id).name for role_id in excluded_roles])
            embed.add_field(name="Excluded roles from link checking", value=excluded_roles_names, inline=False)
        else:
            embed.add_field(name="Excluded roles from link checking", value="None", inline=False)

        return embed

    @commands.Cog.listener()
    async def on_message(self, message):
        author = message.author
        content = message.content

        if not hasattr(author, "guild") or not author.guild:
            return

        guild = author.guild
        api_key = await self.config.guild(guild).api_key()

        if not message.author.bot and await self.config.guild(guild).enabled():
            content = message.content

        # Find all URLs, IPv4, and IPv6 addresses using regular expressions
        urls = re.findall(r'https?://\S+', content)
        ipv4_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
        ipv6_addresses = re.findall(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', content)

        # Merge all addresses and URLs
        all_addresses = urls + ipv4_addresses + ipv6_addresses

        if all_addresses:
            for address in all_addresses:
                if await self.config.guild(guild).debug():
                    log.info(f"Found address: {address}")

                headers = {
                    "x-apikey": api_key
                }

                # Check if the address is an IPv4 or IPv6 address
                if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', address):
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"
                else:
                    url = f"https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(address.encode()).decode().strip('=')}"

                response = requests.get(url, headers=headers)

                if await self.config.guild(guild).debug():
                    log.info(f"Sending RESPONSE: {response}")

                if response.status_code == 200:
                    json_response = response.json()
                    json_data = json_response.get("data", {})  # Extract the "data" object
                    json_attributes = json_data.get("attributes", {})  # Extract the "attributes" object
                    json_last_analysis_stats = json_attributes.get("last_analysis_stats", {})  # Extract the "last_analysis_stats" object
                    malicious = json_last_analysis_stats.get("malicious", 0)  # Extract the "malicious" value
                    suspicious = json_last_analysis_stats.get("suspicious", 0)  # Extract the "suspicious" value
                    total_scanners = json_response["data"]["attributes"]["last_analysis_results"]

                    # Count the total number of vendors
                    total_scanners = len(total_scanners)

                    if (isinstance(malicious, int) and malicious >= 1) or (isinstance(suspicious, int) and suspicious >= 1):
                        await self.handle_bad_link(message, malicious, suspicious, total_scanners)

                    if await self.config.guild(guild).debug():
                        log.info(f"MALICIOUS: {str(malicious)}")
                        log.info(f"SUSPICIOUS: {str(suspicious)}")
                return

    async def send_dm_to_user(self, member, link, dm_title: str, dm_description: str, notes: str):
        embed = discord.Embed(
            description=dm_description,
            title=dm_title,
            color=discord.Color.red()
        )
        embed.set_author(name=f"{member.name}#{member.discriminator}")
        embed.add_field(name="Link:", value="`" + link + "`", inline=False)
        embed.add_field(name="Notes:", value=notes, inline=False)
        embed.add_field(name="Time:", value=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), inline=False)
        try:
            await member.send(embed=embed)
        except discord.errors.Forbidden:
            log.info("You do not have permissions to send a direct message to the user.")
        except discord.errors.HTTPException:
            log.info("Sending a direct message to the user failed.")

    async def send_to_reports_channel(self, guild, member, link, message, report_title, report_description):
        reports_channel_id = await self.config.guild(guild).report_channel()
        reports_channel = guild.get_channel(reports_channel_id)
        message_channel = message.channel

        embed_channel = discord.Embed(
            title=report_title,
            description=report_description,
            color=discord.Color.red()
        )

        embed_channel.add_field(name="User:", value=f"{member.name}#{member.discriminator}", inline=True)
        embed_channel.add_field(name="Channel:", value=message_channel, inline=True)
        embed_channel.add_field(name="Link:", value="`" + link + "`", inline=False)
        embed_channel.add_field(name="Time:", value=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), inline=True)

        if reports_channel:
            try:
                await reports_channel.send(embed=embed_channel)
            except discord.errors.Forbidden:
                log.info("You do not have permissions to send messages to the reports channel.")
            except discord.errors.HTTPException:
                log.info("Sending a message to the reports channel failed.")

    async def determine_mal_sus(self, message, num_malicious, num_suspicious, total_scanners):

        # Format the Title
        if ((isinstance(num_malicious, int) and num_malicious >= 1)): # Malicious Link
            mal_sus = "Malicious "
            if ((isinstance(num_suspicious, int) and num_suspicious >= 1)):
                mal_sus += "and Suspicious "
        elif ((isinstance(num_suspicious, int) and num_suspicious >= 1)):
            mal_sus = "Suspicious Link Found"

        mal_sus += "Link Found"

        # Format the Description
        if ((isinstance(num_malicious, int) and num_malicious >= 1)): # Malicious Link
            message_content = f"Found Malicious by: {str(num_malicious)} of {str(total_scanners)} virus scanners"
            if ((isinstance(num_suspicious, int) and num_suspicious >= 1)):
                message_content += f"\nFound Suspicious by: {str(num_suspicious)} of {str(total_scanners)} virus scanners"
        elif ((isinstance(num_suspicious, int) and num_suspicious >= 1)):
            message_content = f"Found Suspicious by: {str(num_suspicious)} of {str(total_scanners)} virus scanners"

        # Send back the results
        return mal_sus, message_content # Title and Description

    async def handle_bad_link(self, message, num_malicious: int, num_suspicious: int, total_scanners: int):
        member = message.author
        link = message.content

        # Excluded Role IDs
        excluded_roles = await self.config.guild(message.guild).excluded_roles()
        punishment = await self.config.guild(message.guild).punishment_action()
        punishment_channel = await self.config.guild(message.guild).punishment_channel()

        if await self.config.guild(message.guild).debug():
            log.info(f"PUNISH: {punishment}")

        title, description = await self.determine_mal_sus(message, num_malicious, num_suspicious, total_scanners)

        # The Link is Malicious
        if ((isinstance(num_malicious, int) and num_malicious >= 1)):
            if any(role.id in excluded_roles for role in member.roles):
                # Excluded Roles just get a heads up - BYPASS the Punishment Action
                await self.send_dm_to_user(member, link, title, description, f"You have sent a bad link.")
            elif punishment == "ban": # Ban the Sender
                await self.send_dm_to_user(member, link, title, description, f"You have sent a link that is considered malicious and have been banned from the server.")
                try:
                    await message.guild.ban(member, reason="Malicious link detected")
                except discord.errors.Forbidden:
                    log.error("Bot does not have proper permissions to ban the user")
            elif punishment == "warn": # DM Sender on Warn
                await self.send_dm_to_user(member, link, title, description, f"WARNING: You have sent a link that is considered malicious!")
            else: # This is when it's set to Punish
                await self.send_dm_to_user(member, link, title, description, "You have sent a link that is considered malicious and have been disabled from sending further messages.\n"
                                                                            f"You can appeal this status in `{punishment_channel.name}` channel.")
                try: # Remove Existing Roles and Set the punishment_role
                    punishment_role_id = await self.config.guild(message.guild).punishment_role()
                    if punishment_role_id:
                        punishment_role = message.guild.get_role(punishment_role_id)
                        await member.add_roles(punishment_role)
                except discord.errors.Forbidden:
                    log.error(f"Bot does not have permissions to add the {punishment_role.name} role to {member.name}.")
                except discord.errors.HTTPException:
                    log.error(f"Adding the {punishment_role.name} role to {member.name} failed.")

            # Send to the Reports channel
            await self.send_to_reports_channel(message.guild, member, link, message, title, description)

            # Handle the Link Message
            try:
                await message.delete()
            except discord.errors.NotFound:
                log.info("Message not found or already deleted.")
            except discord.errors.Forbidden:
                log.info("Bot does not have proper permissions to delete the message")
            except discord.errors.HTTPException:
                log.info("Deleting the message failed.")
            return

def setup(bot):
    bot.add_cog(VirusTotal(bot))
