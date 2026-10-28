#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble five independent capture runs without accepting failed positives."""
from pathlib import Path
import shutil
import subprocess
import sys

from finalize import finalize
from mutate import derive


def assemble(runs, out):
    here = Path(__file__).resolve().parent
    out.mkdir()  # Reject stale output; never overlay a previous corpus.
    for name in ['explicit', 'connected', 'io', 'msp', 'msp32']:
        run = runs / name
        expected_exit = '1' if name.startswith('msp') else '0'
        if (run / 'logs/scanner.exit').read_text().strip() != expected_exit:
            raise RuntimeError(f'{name}: unexpected endpoint exit; inspect logs')
        shutil.copyfile(run / f'{name}.pcap', out / f'{name}.pcap')
        for filename in ['scanner.log', 'adapter.log', 'tcpdump.log', 'scanner.exit']:
            shutil.copyfile(run / 'logs' / filename, out / f'{name}-{filename}')
    for source, dest in [('image.json', 'generator-image.json'), ('packages.txt', 'generator-packages.txt')]:
        shutil.copyfile(runs / 'explicit/logs' / source, out / dest)
    derive(out / 'io.pcap', out)
    subprocess.run(['bash', str(here / 'export-oracle.sh'), str(out)], check=True)
    finalize(out, here)


if __name__ == '__main__':
    assemble(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
