import argparse
from diffrays.analyzer import run_diff
from diffrays.server import run_server
from diffrays.log import get_logger

logger = get_logger(__name__)

def main():
    parser = argparse.ArgumentParser(prog="diffrays")
    sub = parser.add_subparsers(dest="command", required=True)

    diff_parser = sub.add_parser("diff")
    diff_parser.add_argument("old", help="Path to old binary")
    diff_parser.add_argument("new", help="Path to new binary")
    diff_parser.add_argument("-o", "--output", default="output.sqlite", help="SQLite output file")

    server_parser = sub.add_parser("server")
    server_parser.add_argument("--db-path", required=True)

    args = parser.parse_args()

    if args.command == "diff":
        run_diff(args.old, args.new, args.output)
    elif args.command == "server":
        print(f"Server mode (future): db={args.db_path}")
        logger = get_logger("diffrays.cli")
        logger.info("Launching server for DB: %s", args.db_path)
        run_server(db_path=args.db_path)

if __name__ == '__main__':
    main()