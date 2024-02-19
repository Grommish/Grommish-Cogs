# __init__.py
#
# Copyright 2024 - Donald Hoskins <grommish@gmail.com>
# Released under GNU General Public License v3.0
from .virustotal import VirusTotal

async def setup(bot):
    await bot.add_cog(VirusTotal(bot))
