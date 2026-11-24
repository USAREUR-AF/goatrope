# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""goatrope command line.

  goatrope install   [--config PATH]           apply the declaration (refuses, changing nothing, when unsafe)
  goatrope status    [--config PATH]           what the machine is doing now
  goatrope check     [--config PATH] [--json]  exit 0: matches the declaration; 3: differs; other: error
  goatrope uninstall [--purge]                 remove everything install wrote and restore the ports
  goatrope validate  [--config PATH]           check the declaration alone, without touching the machine
  goatrope relay     [--config PATH]           run the relay (WIP; see docs/adr/0003)

Exit codes: 0 success or match; 2 refused or invalid declaration; 3 check differs; 1 error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import VERSION, config as cfgmod

EXIT_OK, EXIT_ERROR, EXIT_REFUSED, EXIT_DIFFERS = 0, 1, 2, 3


def _need_root() -> None:
    if os.geteuid() != 0:
        print("goatrope: run as root (sudo)", file=sys.stderr)
        sys.exit(EXIT_REFUSED)


def _load(path: str) -> cfgmod.Config:
    cfg = cfgmod.load(path)
    return cfg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="goatrope", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--version", action="version", version=f"goatrope {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("install", "status", "check", "validate", "relay", "apply-ports"):
        p = sub.add_parser(name)
        p.add_argument("--config", default=cfgmod.DEFAULT_PATH)
        if name == "check":
            p.add_argument("--json", action="store_true")
    p = sub.add_parser("uninstall")
    p.add_argument("--purge", action="store_true", help="also remove the declaration and the recordings")
    p = sub.add_parser("run-send")
    p.add_argument("name")
    p.add_argument("--config", default=cfgmod.DEFAULT_PATH)
    p = sub.add_parser("verify-component")
    p.add_argument("kind", choices=["decode"])
    p.add_argument("name")
    p.add_argument("--config", default=cfgmod.DEFAULT_PATH)
    a = ap.parse_args(argv)

    from . import tap
    try:
        if a.cmd == "uninstall":
            _need_root()
            tap.uninstall(a.purge)
            return EXIT_OK
        cfg = _load(a.config)
        if a.cmd == "validate":
            print(f"{a.config}: valid")
            if cfg.tap:
                print(tap.banner(cfg.tap))
            return EXIT_OK
        if a.cmd == "relay":
            from . import relay
            _need_root()
            return relay.run(cfg)
        if cfg.tap is None:
            print("goatrope: this declaration has no [tap]; only `goatrope relay` applies", file=sys.stderr)
            return EXIT_REFUSED
        if a.cmd == "install":
            _need_root()
            print(tap.banner(cfg.tap))
            tap.install(cfg)
            items = tap.check(cfg)
            bad = [i for i in items if i["ok"] is False]
            tap.status(cfg)
            return EXIT_OK if not bad else EXIT_DIFFERS
        if a.cmd == "status":
            return tap.status(cfg)
        if a.cmd == "check":
            items = tap.check(cfg)
            bad = [i for i in items if i["ok"] is False]
            if a.json:
                print(json.dumps({"goatrope": VERSION, "config": a.config, "mode": cfg.tap.mode,
                                  "result": "differs" if bad else "match", "items": items}, indent=2))
            else:
                print(tap.banner(cfg.tap))
                for i in items:
                    mark = {True: "ok  ", False: "DIFF", None: "info"}[i["ok"]]
                    print(f"  {mark} {i['id']}: {i['have']}" + ("" if i["ok"] is not False else f" (want {i['want']})"))
                print("result: " + (f"differs in {len(bad)} item(s)" if bad else "matches the declaration"))
            return EXIT_DIFFERS if bad else EXIT_OK
        if a.cmd == "apply-ports":
            problems = tap.apply_ports(cfg)
            for p in problems:
                print(f"goatrope: {p}", file=sys.stderr)
            return EXIT_ERROR if problems else EXIT_OK
        if a.cmd == "run-send":
            from . import send
            return send.run_send(cfg, a.name)
        if a.cmd == "verify-component":
            from . import send
            return send.verify_component(cfg, a.kind, a.name)
    except cfgmod.ConfigError as e:
        print(f"goatrope: refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    except tap.Refusal as e:
        print(f"goatrope: refused, nothing was changed: {e}", file=sys.stderr)
        return EXIT_REFUSED
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
