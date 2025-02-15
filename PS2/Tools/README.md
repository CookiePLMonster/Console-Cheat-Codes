# NFS Scanner Config Tool (`nfs-scanner-configs.py`)

This tool can dump controls settings (called scanner configs) from PS2 BlackBox NFS games.
It can also be used to create an optimized PNACH with custom scanner configs.

Options:
```
  --elf ELF_PATH             path to game elf (required)
  --event-names EVENT_NAMES_JSON
                        path to the JSON file with event names (required by --dump-scanner-configs and --generate-pnach)
  --scanner-configs SCANNER_CONFIGS_JSON
                        path to the JSON file with scanner configs (required by --generate-pnach)
  --dump-event-names EVENT_NAMES_JSON
                        dump event names to a JSON file
  --dump-scanner-configs SCANNER_CONFIGS_JSON
                        dump scanner configs to a JSON file
  --generate-pnach PNACH_PATH
                        generate a patch file with new scanner configs
```

Usage:
1. Dump the event names (requires specifying the ELF).
2. Dump the scanner configs (requires specifying the ELF and event names).
3. Make the necessary changes in the scanner configs.
4. Create a PNACH patch with the new configs (requires specifying the ELF, event names, and scanner configs).
