# NFS Scanner Config Tool (`nfs-scanner-configs.py`)

This tool can dump controls settings (called scanner configs) from PS2 BlackBox NFS games.
It can also be used to create an optimized PNACH with custom scanner configs.

For usage details, refer to `--help` for each of the subcommands.

Usage:
1. Dump the event names (`event-names dump`).
2. Dump the scanner configs (`scanner-configs dump`).
3. Make the necessary changes in the scanner configs.
4. Create a PNACH patch with the new configs (`scanner-configs patch`).
