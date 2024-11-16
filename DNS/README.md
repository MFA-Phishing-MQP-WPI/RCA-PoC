# `DNS` / `DNS Server`

## Run With:
```bash
.../RCA-PoC/DNS > python3 dns_shell.py
```

<br>

## DNS Workflow
1. Listen for `DNS Resolution Request`s
2. Look up URLs passed in `DNS Resolution Request`s in the [database](database)
3. Respond with `[status code] [port number / error message]`
    - `200 12345`
        - This response means: successfully resolved the URL to port number `12345`
    - `400`
        - This response means: could Not Find URL in [database](database)
    - `403`
        - This response means: `DNS Server` is not authorized to resolve this URL
    - `504`
        - This response means: `DNS Server` has experienced an error and could not resolve the URL due to an unknown reason
     
