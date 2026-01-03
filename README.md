# Minecraft Asset Downloader

> [!WARNING]
> This project is intended to be used ONLY by players who legitimately own the game. There is no authentication built in as Minecraft's own asset servers don't have authentication either, however using this project to download assets and code without owning the game, just like downloading from Minecraft's asset servers, is piracy.

A simple Python script to download Minecraft's version files, libraries, and assets to local folders. This is built with the primary purpose of hosting a local mirror for LAN parties and similar events, but is also designed to detect tampering or removal of old files.
The project keeps a record of hashes of downloaded files, which will be checked for every future download in case changes are made to the files hosted by Mojang.
Files that have been changed on the Mojang servers will not be re-downloaded and must be deleted for a version with the new hash to be downloaded.

Run with `uv run main.py`, or just install Pydantic and aiohttp and run `python main.py`. Configuration is found in `main.py`.
