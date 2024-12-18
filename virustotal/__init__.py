# __init__.py
#
# Copyright 2024 - Donald Hoskins <grommish@gmail.com>
# Released under GNU General Public License v3.0
from .virustotal import VirusTotal
from redbot.core.utils import get_end_user_data_statement

__red_end_user_data_statement__ = get_end_user_data_statement(__file__)

async def setup(bot):
    await bot.add_cog(VirusTotal(bot))
