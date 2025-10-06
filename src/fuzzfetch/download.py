# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch download utils"""

from __future__ import annotations

from logging import getLogger
from time import perf_counter
from typing import TYPE_CHECKING

from requests import Response, Session
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException
from urllib3 import Retry

from .errors import FetcherException

if TYPE_CHECKING:
    from .path import PathArg

HTTP_ADAPTER = HTTPAdapter(
    max_retries=Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
    )
)
HTTP_SESSION = Session()
HTTP_SESSION.mount("https://", HTTP_ADAPTER)

LOG = getLogger("fuzzfetch")


def iec(number: float | int) -> str:
    """Format a number using IEC multi-byte prefixes.

    Arguments:
        number: Number to format.

    Returns:
        Input number, formatted to the largest whole SI prefix.
    """
    prefixes = ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"]
    while number >= 1024:
        number /= 1024.0
        prefixes.pop(0)
    return f"{number:0.2f}{prefixes[0]}"


def si(number: float | int) -> str:  # pylint: disable=invalid-name
    """Format a number using SI prefixes.

    Arguments:
        number: Number to format.

    Returns:
        Input number, formatted to the largest whole SI prefix.
    """
    prefixes = ["", "k", "M", "G", "T", "P", "E", "Z", "Y"]
    while number >= 1000:
        number /= 1000.0
        prefixes.pop(0)
    return f"{number:0.2f}{prefixes[0]}"


def get_url(url: str, timeout: float | None = None) -> Response:
    """Retrieve requested URL"""
    try:
        data = HTTP_SESSION.get(url, stream=True, timeout=timeout)
        data.raise_for_status()
    except RequestException as exc:
        raise FetcherException(exc) from None

    return data


def resolve_url(url: str, timeout: float | None = None) -> Response:
    """Resolve requested URL"""
    try:
        data = HTTP_SESSION.head(url, timeout=timeout)
        data.raise_for_status()
    except RequestException as exc:
        raise FetcherException(exc) from None

    return data


def download_url(url: str, outfile: PathArg, timeout: float | None = 30.0) -> None:
    """Download a URL to a local path.

    Arguments:
        url: URL to download.
        outfile: Path to output file.
        timeout: Number of seconds to wait for a response.
    """
    downloaded = 0
    start_time = report_time = perf_counter()
    resp = get_url(url, timeout)
    try:
        total_size = int(resp.headers["Content-Length"])
        LOG.info("> Downloading: %s (%sB total)", url, iec(total_size))
    except KeyError:
        total_size = None
        LOG.info("> Downloading: %s (unknown size)", url)
    with open(outfile, "wb") as build_zip:
        try:
            for chunk in resp.iter_content(256 * 1024):
                build_zip.write(chunk)
                downloaded += len(chunk)
                now = perf_counter()
                if (now - report_time) > 30 and downloaded != total_size:
                    if total_size is None:
                        LOG.info(
                            ".. still downloading (%sB, %sB/s)",
                            iec(downloaded),
                            si(float(downloaded) / (now - start_time)),
                        )
                    else:
                        LOG.info(
                            ".. still downloading (%0.1f%%, %sB/s)",
                            100.0 * downloaded / total_size,
                            si(float(downloaded) / (now - start_time)),
                        )
                    report_time = now
        except RequestException as exc:
            raise FetcherException(exc) from None
    LOG.info(
        ".. downloaded (%sB/s)", si(float(downloaded) / (perf_counter() - start_time))
    )
