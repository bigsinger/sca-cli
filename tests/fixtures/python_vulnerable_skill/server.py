"""Sample vulnerable skill server module."""

import requests
import urllib3


def fetch_data(url: str) -> dict:
    """Fetches data from the given URL using requests library."""
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    result = fetch_data("https://example.com/api/data")
    print(result)
