# pytap

pytap is a library to query the Proofpoint TAP API for information on click events, VAPs, IOCs, and campaign data.

## Requirements

A licensed Proofpoint TAP instance to generate a Service Principal and Secret.

## Setting the TAP Auth Token

```python
self.tap_token = ('your TAP service principal', 'your TAP service secret')
```

## Usage

```python
# Import the library
from pytap import pytap

# Initialize Auth Token and TAP API base URL
fetch = pytap()

# Query the Campaign API
fetch.tap_campaign('your campaignid')

# Query the Forensics API
fetch.tap_forensics('your threatid')

# Query the People API
fetch.tap_people('time window')

# Query the Threat API
fetch.tap_threat('your threatid')

# Query the SIEM API
fetch.tap_siem('5')
```

## Helpful hints for using the TAP API

- The People API allows administrators to identify which users in their organizations were most attacked during a specified period. Supply an integer less than or equal to 90 days to query for VAPs during that period

- The SIEM API has (6) possible endpoints. Specify which one you would like to query using the appropriate position:
    - [0] Blocked Clicks
    - [1] Permitted Clicks
    - [2] Messages Blocks
    - [3] Messages Delivered
    - [4] Issues
    - [5] All

## Query Examples
```python
fetch.tap_campaign('9f321206-f4ca-4c4f-b096-410ec9d6fb0c')
fetch.tap_forensics('119b854d8ad4c1ea48c1584a0681c1fd9ddda1a14f9df6c610135cb9b7316467')
fetch.tap_people('30')
fetch.tap_threat('119b854d8ad4c1ea48c1584a0681c1fd9ddda1a14f9df6c610135cb9b7316467')
fetch.tap_siem('5')
```
## Contributing
Pull requests are welcome. For major changes, please open an issue to discuss what you would like to change.

## Authors
[Jason Ford](https://twitter.com/JasonFord)

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
