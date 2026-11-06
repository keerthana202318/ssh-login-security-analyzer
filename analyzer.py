import re
import csv
import argparse
from collections import Counter
from datetime import datetime


def analyze_logs(log_file, threshold, output_file):

    failed_attempts = Counter()

    pattern = r"Failed password.*from (\d{1,3}(?:\.\d{1,3}){3})"

    try:
        with open(log_file, "r") as file:

            for line in file:

                match = re.search(pattern, line)

                if match:
                    ip = match.group(1)
                    failed_attempts[ip] += 1

        print("\n===== SSH LOGIN SECURITY REPORT =====")
        print("Generated:", datetime.now())
        print("Threshold:", threshold)
        print("-------------------------------------")

        if not failed_attempts:
            print("No failed SSH login attempts found.")

        for ip, count in failed_attempts.most_common():

            status = "SUSPICIOUS" if count >= threshold else "Normal"

            print(f"IP: {ip} | Attempts: {count} | Status: {status}")

        with open(output_file, "w", newline="") as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow(["IP Address", "Failed Attempts", "Status"])

            for ip, count in failed_attempts.most_common():

                status = "SUSPICIOUS" if count >= threshold else "Normal"

                writer.writerow([ip, count, status])

        print("-------------------------------------")
        print("Report saved to:", output_file)

    except FileNotFoundError:
        print("Error: Log file not found:", log_file)


def main():

    parser = argparse.ArgumentParser(
        description="SSH Login Security Analyzer"
    )

    parser.add_argument(
        "--log",
        default="sample_auth.log",
        help="Authentication log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed attempts to flag an IP"
    )

    parser.add_argument(
        "--output",
        default="security_report.csv",
        help="CSV report filename"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1")

    analyze_logs(args.log, args.threshold, args.output)


if __name__ == "__main__":
    main()
