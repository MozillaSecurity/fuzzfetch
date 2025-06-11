# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""Fuzzfetch download module tests"""

from itertools import count

import pytest  # pylint: disable=import-error

from fuzzfetch.download import (
    FetcherException,
    download_url,
    get_url,
    iec,
    resolve_url,
    si,
)


@pytest.mark.parametrize(
    "number, expected",
    [
        (1024, "1.00Ki"),
        (1048576, "1.00Mi"),
        (1073741824, "1.00Gi"),
        (500, "500.00"),
    ],
)
def test_iec(number, expected):
    """Test iec function to format numbers using IEC prefixes."""
    assert iec(number) == expected


@pytest.mark.parametrize(
    "number, expected",
    [
        (1000, "1.00k"),
        (1000000, "1.00M"),
        (1000000000, "1.00G"),
        (500, "500.00"),
    ],
)
def test_si(number, expected):
    """Test si function to format numbers using SI prefixes."""
    assert si(number) == expected


def test_get_url_success(requests_mock):
    """Test get_url with valid URL to return a successful response."""
    url = "http://example.com"
    requests_mock.get(url, text="success")

    response = get_url(url)

    assert response.status_code == 200
    assert response.text == "success"


def test_get_url_exception(requests_mock):
    """Test get_url raises FetcherException on a failed request."""
    url = "http://example.com"
    requests_mock.get(url, status_code=404)

    with pytest.raises(FetcherException):
        get_url(url)


def test_resolve_url_success(requests_mock):
    """Test resolve_url with valid URL to return a successful response."""
    url = "http://example.com"
    requests_mock.head(url, text="")

    response = resolve_url(url)

    assert response.status_code == 200


def test_resolve_url_exception(requests_mock):
    """Test resolve_url raises FetcherException on a failed request."""
    url = "http://example.com"
    requests_mock.head(url, status_code=404)

    with pytest.raises(FetcherException):
        resolve_url(url)


def test_download_url_success(mocker, requests_mock, tmp_path):
    """Test download_url to download content to a file with a known size."""
    url = "http://example.com"
    data = b"some data" * 10  # Mock data
    requests_mock.get(url, content=data, headers={"Content-Length": str(len(data))})
    # perf_counter() increasing by 0.1s every call
    mocker.patch(
        "fuzzfetch.download.perf_counter", autospec=True, side_effect=count(1.0, 0.1)
    )

    output_file = tmp_path / "output_file"
    download_url(url, output_file, timeout=30.0)

    assert output_file.read_bytes() == data


def test_download_url_unknown_size(mocker, requests_mock, tmp_path):
    """Test download_url to download content when the size is unknown."""
    url = "http://example.com"
    data = b"some data" * 5
    requests_mock.get(url, content=data)  # No Content-Length header
    # perf_counter() increasing by 0.1s every call
    mocker.patch(
        "fuzzfetch.download.perf_counter", autospec=True, side_effect=count(1.0, 0.1)
    )

    output_file = tmp_path / "output_file"
    download_url(url, output_file, timeout=30.0)

    assert output_file.read_bytes() == data


def test_download_url_exception(mocker, requests_mock, tmp_path):
    """Test download_url raises FetcherException on a failed download."""
    url = "http://example.com"
    requests_mock.get(url, status_code=500)
    # perf_counter() increasing by 0.1s every call
    mocker.patch(
        "fuzzfetch.download.perf_counter", autospec=True, side_effect=count(1.0, 0.1)
    )

    output_file = tmp_path / "output_file"
    with pytest.raises(FetcherException):
        download_url(url, output_file, timeout=30.0)
