# CrowdBehavior

A simple utility using [FalconPy](https://github.com/CrowdStrike/falconpy) to print detection details from a CrowdStrike console as a readable table.

# Usage

Install dependencies with `pip`:

```bash
$ pip install -r requirements.txt
```

Then just run:
```bash
$ python3 crowdbehaviors.py --client-id <YOUR_CLIENT_ID> --secret <YOUR_SECRET>
```

## Optional Flags
* `--limit`. Maximum number of detections to extract.
* `--offset`. Offset for detections query.
* `--sort`. Sorting criteria for detections query.
* `--filter`. Filter to use for detections query.
* `--json`. Dump detection objects as JSON instead of showing table of behaviors.
* `--detections-only`. Show detections only - not their individual behaviors.