# Update Shodan

Python script to update a home network Shodan monitor

Retrieve the current IP address
Check if the IP has changed
Update the Shodan alert for the home IP, if changed
Initiate a scan, if changed

## Usage

```
Usage: update-shodan [OPTIONS] [SHODAN_API_KEY]

 Command line interface for updating Shodan alerts for the home network.
 This function retrieves the current public IP address, checks if it has changed, and
 updates the Shodan alert for the home network if necessary. It also initiates a new
 Shodan scan if the IP address has changed.

╭─ Arguments ───────────────────────────────────────────────────────────────────────────╮
│   shodan_api_key      [SHODAN_API_KEY]  Shodan API key [env var: SHODAN_API_KEY]      │
╰───────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ─────────────────────────────────────────────────────────────────────────────╮
│ --dry-run  -d               Dry run                                                   │
| --print    -p               Print Shodan alerts and exit                              │
│ --clean    -c               Remove all other IPs from the Shodan alert                │
│ --no-scan  -n               Don't start a new Shodan scan                             │
│ --verbose  -v      INTEGER  Verbose mode. Repeat for increased verbosity [default: 0] │
│ --version  -V                                                                         │
│ --help     -h               Show this message and exit.                               │
╰───────────────────────────────────────────────────────────────────────────────────────╯
```
