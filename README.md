# Mind the CORS

Source code of the tools used in the paper **Mind the CORS**, published at the IEEE TPS 2023 conference.

## CORS Flaws Scanner

Run the scanner against a target domain:

```bash
python3 cors.py -t example.com
```

Use the `-h` flag to see all available options.

Run the scanner against a list of domains:

```bash
python3 launcher.py -s sites.txt
```

The launcher also supports `.csv` files in the format of the [Tranco ranking](https://tranco-list.eu/) list.
