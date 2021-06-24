# coding=utf-8
"""fuzzfetch download utils"""
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import time
from logging import getLogger
from typing import Union

from requests import Response, Session
from requests.exceptions import RequestException

from . import FetcherException
from .path import PathArg

HTTP_SESSION = Session()
LOG = getLogger("fuzzfetch")


def iec(number: Union[float, int]) -> str:
    """Format a number using IEC multi-byte prefixes.

    Arguments:
        number: Number to format.

    Returns:
        Input number, formatted to the largest whole SI prefix.
    """
    prefixes = ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi"]
    while number > 1024:
        number /= 1024.0
        prefixes.pop(0)
    return f"{number:0.2f}{prefixes[0]}"


def si(number: Union[float, int]) -> str:  # pylint: disable=invalid-name
    """Format a number using SI prefixes.

    Arguments:
        number: Number to format.

    Returns:
        Input number, formatted to the largest whole SI prefix.
    """
    prefixes = ["", "k", "M", "G", "T", "P", "E", "Z", "Y"]
    while number > 1000:
        number /= 1000.0
        prefixes.pop(0)
    return f"{number:0.2f}{prefixes[0]}"


def get_url(url: str) -> Response:
    """Retrieve requested URL"""
    try:
        data = HTTP_SESSION.get(url, stream=True)
        data.raise_for_status()
    except RequestException as exc:
        raise FetcherException(exc) from None

    return data


def resolve_url(url: str) -> Response:
    """Resolve requested URL"""
    try:
        data = HTTP_SESSION.head(url)
        data.raise_for_status()
    except RequestException as exc:
        raise FetcherException(exc) from None

    return data


def download_url(url: str, outfile: PathArg) -> None:
    """Download a URL to a local path.

    Arguments:
        url: URL to download.
        outfile: Path to output file.
    """
    downloaded = 0
    start_time = report_time = time.time()
    resp = get_url(url)
    total_size = int(resp.headers["Content-Length"])
    LOG.info("> Downloading: %s (%sB total)", url, iec(total_size))
    with open(outfile, "wb") as build_zip:
        for chunk in resp.iter_content(1024 * 1024):
            build_zip.write(chunk)
            downloaded += len(chunk)
            now = time.time()
            if (now - report_time) > 30 and downloaded != total_size:
                LOG.info(
                    ".. still downloading (%0.1f%%, %sB/s)",
                    100.0 * downloaded / total_size,
                    si(float(downloaded) / (now - start_time)),
                )
                report_time = now
    LOG.info(
        ".. downloaded (%sB/s)", si(float(downloaded) / (time.time() - start_time))
    )
