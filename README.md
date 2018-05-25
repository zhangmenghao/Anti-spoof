# NetHCF: Filtering Spoofed IP Traffic Using Switching ASICs
This is a introduction to our NetHCF project.
## Overview
We implement a switch which could apply Hop-Count-Filtering on its received packets.
Based on this the switch is able to anti spoofing based attacks(e.g.SYN Flood)

## Design
### Modeling
We set up a relatively simple model with h1-s1-h2 topology. We assume that h1 acts as a client(normal or attacker) which is ahead of the switch and h2 acts as a server which is behind the server.
### Workflow
Please refer to our paper.
## Test
The method to start the p4 switch is to set up a topology on **mininet** where we run the switch.

1. Run `run_demo.sh` to start the switch on the topology defined in `topo.py`
2. Run a simple web server and client according to [mininet walkthrough](http://mininet.org/walkthrough/#run-a-simple-web-server-and-client). And then, just try!

## Source Code
`p4src/hop_count.p4`  This is the p4 source code.

`p4src/includes/headers.p4`  This is the p4 code which defines the header used in NetHCF.

`p4src/includes/parser.p4`  This is the p4 code which defines the parser graph of NetHCF.

`control.py` NetHCF's conrol program running on CPU, masters the state switch triggered by the number of last period's abnormal packets.

`topo.py` This script will set up the topology of this model and starts the CLI of p4 switch.

`run_demo.sh` Start the switch on the topology defined in `topo.py` without log.

`commands.txt` There are table entries here, which will be loaded into the swtich by `topo.py`. You can also add the entries manually through CLI.

`env.sh` Set p4 related environment variables.

`cleanup.sh` Clean up the environment such as the pcap file and accessed webpage.
