#!/usr/bin/env python3
import os
import re
import time
import urllib.parse as url
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List

import pandas as pd
import requests

data_path = Path("../") / "data"
cve_data = pd.read_feather(data_path / "all_parsed_cve_references.feather")
github_links = cve_data.loc[
    cve_data["url"].str.contains("github.com"), "url"
].drop_duplicates()

# Global used to track when scrip must pause to prevent getting errors
# and get as much data as we can as fast as we can.
timer = 0


def handle_get_requests(api_url, headers=None, data=None, time_to_wait=3, api_token=""):
    global timer
    """
    Uses the GitHub API response to wait as appropriate for the specified time after
    called.
    """
    if timer > 0:
        x = 60
        while timer:
            hours = int(timer / x / x)
            minutes = int(timer / x) - (hours * x)
            print(
                f"Waiting for {hours:02d}:{minutes:02d} (hh:mm)", flush=True, end="\r"
            )
            y = min(timer, x)
            time.sleep(y)
            timer -= x

    req_headers = {}
    if headers:
        req_headers |= headers

    if api_token:
        req_headers["Authorization"] = f"Bearer {api_token}"
    response = requests.get(api_url, headers=req_headers, data=data)

    resp_headers = response.headers
    requests_left = int(resp_headers["x-ratelimit-remaining"])
    time_left = int(resp_headers["x-ratelimit-reset"]) - datetime.now().timestamp()
    if time_left > 0:
        time_to_wait = time_left

    wait_more = requests_left <= 1
    timer = time_to_wait if wait_more else 0
    return response


def get_github_repo_paths(raw_urls: pd.Series) -> pd.Series:
    # Get each part of the URL and pull out just the repo path
    url_parts = raw_urls.str.strip().apply(url.urlsplit)

    # Github Repo Links are the first two parts of the "path"
    repo_paths = (
        url_parts.apply(lambda x: x.path)
        .str.split("/")
        .apply(lambda x: "/".join(x[:3]))
    )

    # return the final reconstructed URL to each repo
    return ("https://api.github.com/repos" + repo_paths).drop_duplicates()


def get_github_data(
    api_url: str, headers=None, data=None, endpoint="", api_token=""
) -> Dict[str, Dict]:
    the_url = f"{api_url}/{endpoint}"
    response = handle_get_requests(the_url, api_token=api_token)
    print(".", end="", flush=True)
    if response.status_code != 200:
        return pd.Series(
            {
                "url": api_url,
                "status": "failed",
                endpoint: {
                    "status_code": str(response.status_code),
                    "text": response.text,
                },
            }
        )
    if contrib_resp := response.json():
        return pd.Series({"url": api_url, "status": "success", endpoint: contrib_resp})
    return pd.Series({"url": api_url, "status": "", endpoint: {}})


def get_api_token(file_path=Path("api_token.secret")):
    file_path = Path(file_path)
    if file_path.exists():
        with open(file_path, "r") as secret_path:
            return secret_path.readline().strip()
    else:
        return None


def main():
    start = 0  # Set this to your assigned start values.
    batch_size = (
        50  # Needs to be half the max of 5000, leaving some room for error too.
    )

    api_token = get_api_token()

    # Put repo paths and netloc together to get repo links.
    github_repo_urls = get_github_repo_paths(github_links)

    if previous_contrib_data_list := [
        pd.read_feather(contrib_file)
        for contrib_file in data_path.glob("contributors*.feather")
    ]:
        contrib_github_data = pd.concat(previous_contrib_data_list)
        previous_urls = contrib_github_data["url"]

        # Filter out previously queried URLs
        original_len = len(github_repo_urls)
        done_filter = github_repo_urls.isin(previous_urls)
        github_repo_urls = github_repo_urls[~done_filter]
        new_len = len(github_repo_urls)
        print(f"Removed {original_len-new_len} URLs since they were already done.")

    # Set up the end point for this batch
    end = min((start + batch_size), len(github_repo_urls))

    # Check for rate-limit first
    _ = get_github_data(
        "https://api.github.com", endpoint="rate_limit", api_token=api_token
    )

    for i in range(start, end, batch_size):
        # Query GitHub API for languages
        language_col = "languages"
        languages = github_repo_urls.iloc[start:end].apply(
            get_github_data, endpoint=language_col, api_token=api_token
        )
        languages = languages.reset_index().rename(columns={"index": "original_index"})
        try:
            languages.to_feather(data_path / f"languages_{str(i).zfill(5)}.feather")
        except Exception as e:
            breakpoint()
            print(e)

        # Query GitHub API for contributors
        contrib_col = "contributors"
        contributors = github_repo_urls.iloc[start:end].apply(
            get_github_data, endpoint=contrib_col, api_token=api_token
        )
        contributors = contributors.reset_index().rename(
            columns={"index": "original_index"}
        )
        contributors = contributors.explode(contrib_col).reset_index(drop=True)
        try:
            contributors.to_feather(
                data_path / f"contributors_{str(i).zfill(5)}.feather"
            )
        except Exception as e:
            breakpoint()
            print(e)
        print(f"finished up to: {end}")


if __name__ == "__main__":
    main()
