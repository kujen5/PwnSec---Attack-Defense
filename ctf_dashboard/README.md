[![Go Report Card](https://goreportcard.com/badge/github.com/C4T-BuT-S4D/ctf_dashboard)](https://goreportcard.com/report/github.com/C4T-BuT-S4D/ctf_dashboard)
[![release](https://github.com/C4T-BuT-S4D/ctf_dashboard/actions/workflows/release.yml/badge.svg)](https://github.com/C4T-BuT-S4D/ctf_dashboard/actions/workflows/release.yml)

# ctf_dashboard

Dashboard centralising all A&D CTF tools
- Change config
    ```python
    auth: # Change as needed
    username: PwnSec
    password: 'pwnsec'

    game: # Change with the competition you join
    board: "http://127.0.0.1:8000"
    end: "2025-10-26 21:00:00+07:00"

    vulnboxes: # Change with your vulnbox ip and services 
    - user: pwnsec 
        host: 127.0.0.1
        goxy_port: 8000
        services:
        - name: tcp_example
            port: 1338
            proto: tcp
        - name: http_example
            port: 5001
            proto: http

    farm: # Your farm
    addr: 127.0.0.1:5137

    neo:
    addr: 127.0.0.1:5005
    version: '2.0'
    ```
    
- Config path `/resources` as needed (Ex: ssh_key, sample script to exploit)

- Run `./dash`
