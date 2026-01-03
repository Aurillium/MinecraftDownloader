import asyncio
import hashlib
import json
import logging
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from types import CoroutineType
from typing import Any

import aiohttp
from pydantic import BaseModel, Field

# The following folders can be rehosted statically to form a Minecraft version cache
# These are automatically gathered during run.
# PISTON_NAME:
# - launcher.mojang.com
# - launchermeta.mojang.com
# - piston-meta.mojang.com
# - piston-data.mojang.com
# LIBRARIES_NAME:
# - libraries.minecraft.net
# RESOURCES_NAME:
# - resources.download.minecraft.net
#
# MANIFEST_FILE should be hosted at MANIFEST_URL

MAX_ATTEMPTS: int = 5
MAX_CONNECTIONS: int = 32
BUFFER_SIZE: int = 4096
ASSETS_URL: str = "https://resources.download.minecraft.net/"
MANIFEST_URL: str = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
MANIFEST_FILE: Path = Path("version_manifest.json")
VERSION_META_FOLDER: Path = Path("version_metadata_cache")
HASH_COLLECTION_FILE: Path = Path("url_hashes.json")
PISTON_NAME: str = "piston"
LIBRARIES_NAME: str = "libraries"
RESOURCES_NAME: str = "resources"

LOG_FILE: str = "downloader.log"
LOG_LEVEL = logging.INFO
FILE_LOG_FORMAT = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
)
CONSOLE_LOG_FORMAT = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"
)
LOGGER: logging.Logger = logging.getLogger(__name__)
ch: logging.Handler = logging.StreamHandler(sys.stderr)
ch.setLevel(LOG_LEVEL)
ch.setFormatter(CONSOLE_LOG_FORMAT)
fh: logging.Handler = logging.FileHandler(LOG_FILE)
fh.setLevel(LOG_LEVEL)
fh.setFormatter(FILE_LOG_FORMAT)

HOSTNAMES_DISCOVERED: dict[str, set[str]] = {}
URL_HASHES: dict[str, tuple[str, int]]


class HTTPError(Exception):
    pass


class HashMismatch(ValueError):
    pass


class DownloadError(Exception):
    pass


class VersionManifestLatest(BaseModel):
    release: str
    snapshot: str


class MetadataDownloadInfo(BaseModel):
    id: str
    type: str
    url: str
    time: datetime
    release_time: datetime = Field(alias="releaseTime")
    sha1: str
    compliance_level: int = Field(alias="complianceLevel")


class VersionManifest(BaseModel):
    latest: VersionManifestLatest
    versions: list[MetadataDownloadInfo]


class FileDownload(BaseModel):
    sha1: str
    size: int
    url: str


class VersionMetadataAssetIndex(FileDownload):
    id: str
    total_size: int = Field(alias="totalSize")


class VersionMetadataLibraryDownloadArtifact(FileDownload):
    path: str


class VersionMetadataLibraryDownload(BaseModel):
    artifact: VersionMetadataLibraryDownloadArtifact | None = Field(default=None)
    classifiers: dict[str, VersionMetadataLibraryDownloadArtifact] | None = Field(
        default=None
    )
    # name: str


class VersionMetadataLibrary(BaseModel):
    downloads: VersionMetadataLibraryDownload


class VersionMetadataLoggingClientFile(FileDownload):
    id: str


class VersionMetadataLoggingClient(BaseModel):
    file: VersionMetadataLoggingClientFile
    type: str
    argument: str


class VersionMetadataLogging(BaseModel):
    client: VersionMetadataLoggingClient


# Only parse important info
class VersionMetadata(BaseModel):
    asset_index: VersionMetadataAssetIndex = Field(alias="assetIndex")
    downloads: dict[str, FileDownload]
    libraries: list[VersionMetadataLibrary]
    # Not present in older versions (14w27b and below)
    logging: VersionMetadataLogging | None = Field(default=None)


class MinecraftAsset(BaseModel):
    hash: str
    size: int


class MinecraftAssets(BaseModel):
    objects: dict[str, MinecraftAsset]


# These arguments are required for a handler
def write_hashes(_1=None, _2=None):
    with HASH_COLLECTION_FILE.open("w+") as f:
        json.dump(URL_HASHES, f)


def validate_sha1(location: Path, expected: str) -> bool:
    hasher = hashlib.sha1()
    with location.open("rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    calculated: str = hasher.hexdigest()
    if calculated != expected:
        # Delete file if hash mismatch
        location.unlink()
        return False
    return True


# Raises exception or returns a path that exists
async def download_file(
    base: str, session: aiohttp.ClientSession, url: str, sha1: str
) -> Path:
    global URL_HASHES

    # For gathering hostnames
    hostname: str = url.split("/")[2]
    if base not in HOSTNAMES_DISCOVERED:
        HOSTNAMES_DISCOVERED[base] = set()
    HOSTNAMES_DISCOVERED[base].add(hostname)
    # Removes 'https://host/'
    url_parts: Path = Path(*url.split("/")[3:])
    location: Path = VERSION_META_FOLDER / base / url_parts

    if url in URL_HASHES:
        existing: str
        added: int
        existing, added = URL_HASHES[url]
        added_date: datetime = datetime.fromtimestamp(added)
        if existing != sha1:
            LOGGER.error(
                f"POTENTIAL TAMPERING: File {location} previously downloaded under hash {existing} at {added_date} is now listed under hash {sha1}."
            )
            if location.exists():
                LOGGER.error(
                    f"Will not re-download file as it already exists. If a re-download is required, please delete '{location}'."
                )
                return location
            else:
                LOGGER.warning(
                    "As the original has been deleted, the file will be downloaded under the new hash."
                )
                URL_HASHES[url] = (sha1, int(time.time()))
    else:
        # Store URL hash to ensure it doesn't change later
        URL_HASHES[url] = (sha1, int(time.time()))

    if location.exists():
        if validate_sha1(location, sha1):
            LOGGER.debug(f"Cached version of '{url}' found.")
            return location
        else:
            LOGGER.warning(f"Hash mismatch for '{location}', retrying.")
    location.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            response: aiohttp.ClientResponse = await session.get(url)
            if not response.ok:
                raise HTTPError(response.status)
            hasher = hashlib.sha1()
            try:
                with location.open("wb+") as f:
                    while True:
                        chunk = await response.content.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        f.write(chunk)
            except Exception as e:
                location.unlink()
                raise e
            calculated: str = hasher.hexdigest()
            if calculated != sha1:
                # Delete file if hash mismatch
                location.unlink()
                raise HashMismatch(calculated)
            # Success
            break
        except Exception as e:
            LOGGER.error(f"Error on attempt {attempt + 1} for '{url}':")
            LOGGER.exception(e)
            LOGGER.error("Will attempt to retry.")
            last_error = e
    else:
        LOGGER.error(
            f"URL '{url}' still failing after {MAX_ATTEMPTS} attempts. Raising failure."
        )
        if last_error is not None:
            raise last_error
        # Should not be possible to reach
        raise DownloadError(f"Download still failing after {MAX_ATTEMPTS} attempts.")
    LOGGER.debug(f"Downloaded '{url}' successfully.")
    return location


async def download_metadata(
    session: aiohttp.ClientSession, download_data: MetadataDownloadInfo
) -> None:
    service: str = PISTON_NAME
    LOGGER.info(f"Found new path for version {download_data.id}.")
    try:
        location: Path = await download_file(
            service, session, download_data.url, download_data.sha1
        )
    except HTTPError as e:
        LOGGER.error(
            f"Error: metadata download for version {download_data.id} returned status code {e}. Skipping."
        )
        return
    except HashMismatch as e:
        LOGGER.error(
            f"Provided hash for '{download_data.url}' ({download_data.sha1}) does not match calculated hash '{e}'."
        )
        return
    LOGGER.info(
        f"Successfully downloaded version metadata for {download_data.id} from {download_data.url}."
    )
    # The metadata file now exists, so we can read it
    with location.open("r") as f:
        meta: VersionMetadata = VersionMetadata.model_validate_json(f.read())
        LOGGER.info(f"Downloading jarfiles and mappings for {download_data.id}...")
        tasks: list[CoroutineType] = []
        for download in meta.downloads.values():
            tasks.append(
                download_file(PISTON_NAME, session, download.url, download.sha1)
            )
        await asyncio.gather(*tasks)
        tasks.clear()
        LOGGER.info(f"Downloading libraries for {download_data.id}...")
        for library in meta.libraries:
            if library.downloads.artifact is not None:
                tasks.append(
                    download_file(
                        LIBRARIES_NAME,
                        session,
                        library.downloads.artifact.url,
                        library.downloads.artifact.sha1,
                    )
                )
            if library.downloads.classifiers is not None:
                for classifier in library.downloads.classifiers.values():
                    tasks.append(
                        download_file(
                            LIBRARIES_NAME,
                            session,
                            classifier.url,
                            classifier.sha1,
                        )
                    )
        await asyncio.gather(*tasks)
        tasks.clear()
        LOGGER.info(f"Downloading logging data for {download_data.id}...")
        if meta.logging is not None:
            file: FileDownload = meta.logging.client.file
            await download_file(PISTON_NAME, session, file.url, file.sha1)
        LOGGER.info(f"Downloading asset index for {download_data.id}...")
        asset_location: Path = await download_file(
            PISTON_NAME, session, meta.asset_index.url, meta.asset_index.sha1
        )
        with asset_location.open("r") as f:
            assets: MinecraftAssets = MinecraftAssets.model_validate_json(f.read())
        LOGGER.info(f"Downloading assets for {download_data.id}...")
        for asset in assets.objects.values():
            url: str = ASSETS_URL + asset.hash[:2] + "/" + asset.hash
            tasks.append(download_file(RESOURCES_NAME, session, url, asset.hash))
        await asyncio.gather(*tasks)
        tasks.clear()
        LOGGER.info(f"Done {download_data.id}!")


async def async_main():
    global URL_HASHES

    logging.basicConfig(level=LOG_LEVEL, handlers=[ch, fh])

    if HASH_COLLECTION_FILE.exists():
        with HASH_COLLECTION_FILE.open("r") as f:
            URL_HASHES = json.load(f)
    else:
        URL_HASHES = {}

    signal.signal(signal.SIGUSR1, write_hashes)

    try:
        # 100 conncetions can be made at a time by default
        connector = aiohttp.TCPConnector(limit=MAX_CONNECTIONS)
        async with aiohttp.ClientSession(connector=connector) as session:
            parsed: dict[str, Any]
            if not MANIFEST_FILE.exists():
                LOGGER.info("Downloading version info...")
                response: aiohttp.ClientResponse = await session.get(MANIFEST_URL)
                if not response.ok:
                    LOGGER.error(
                        f"Error: version manifest returned status code {response.status}."
                    )
                    return
                parsed = await response.json()
                with MANIFEST_FILE.open("w+") as f:
                    json.dump(parsed, f)
            else:
                LOGGER.info("Using cached version manifest file.")
                with MANIFEST_FILE.open("r") as f:
                    parsed = json.load(f)

            manifest: VersionManifest = VersionManifest.model_validate(parsed)
            LOGGER.info(
                f"Found {len(manifest.versions)} versions, latest release: '{manifest.latest.release}', latest snapshot: '{manifest.latest.snapshot}'"
            )
            # Create version manifest cache folder if not exists
            if not VERSION_META_FOLDER.exists():
                VERSION_META_FOLDER.mkdir(parents=True)
            LOGGER.info("Beginning to download metadata starting at oldest...")
            tasks: list[CoroutineType] = []
            # Download metadata, which will download assets too
            for version in reversed(manifest.versions):
                # This can be used to debug:
                await download_metadata(session, version)
                # tasks.append(download_metadata(session, version))
            # await asyncio.gather(*tasks)
    except Exception as e:
        raise e
    finally:
        write_hashes()
        LOGGER.info("Gathered hostnames:")
        for service in HOSTNAMES_DISCOVERED:
            LOGGER.info("  " + service + ":")
            for hostname in HOSTNAMES_DISCOVERED[service]:
                LOGGER.info("  - " + hostname)


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    LOGGER.debug("Entering main.")
    main()
