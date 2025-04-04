import argparse
import logging
import os
import sys
import json
from typing import List, Dict, Any
import statistics
import math

# Constants
LOG_FILE = "pa_permission_anomaly_detector.log"
DEFAULT_SENSITIVITY = 2.0  # Standard deviations for anomaly detection


# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Detects anomalous permission assignments based on historical data."
    )
    parser.add_argument(
        "--data-file",
        type=str,
        required=True,
        help="Path to the JSON file containing historical permission data.",
    )
    parser.add_argument(
        "--sensitivity",
        type=float,
        default=DEFAULT_SENSITIVITY,
        help=f"Sensitivity level (number of standard deviations from the mean). Default: {DEFAULT_SENSITIVITY}",
    )
    parser.add_argument(
        "--report-file",
        type=str,
        default="anomaly_report.json",
        help="Path to the JSON file where the anomaly report will be saved.",
    )

    return parser


def load_permission_data(data_file: str) -> List[Dict[str, Any]]:
    """
    Loads permission data from a JSON file.

    Args:
        data_file (str): The path to the JSON data file.

    Returns:
        List[Dict[str, Any]]: A list of permission data dictionaries.

    Raises:
        FileNotFoundError: If the data file does not exist.
        json.JSONDecodeError: If the data file is not a valid JSON file.
        ValueError: If the data file doesn't contain a list of dictionaries.
    """
    try:
        with open(data_file, "r") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError("The data file must contain a list of dictionaries.")

        for item in data:
            if not isinstance(item, dict):
                raise ValueError("The data file must contain a list of dictionaries.")
        return data
    except FileNotFoundError:
        logging.error(f"Data file not found: {data_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON data: {e}")
        raise
    except ValueError as e:
        logging.error(f"Invalid data format: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def analyze_permissions(data: List[Dict[str, Any]], sensitivity: float) -> List[Dict[str, Any]]:
    """
    Analyzes permission data to identify anomalies based on historical data.

    Args:
        data (List[Dict[str, Any]]): A list of permission data dictionaries.
          Each dictionary should contain keys like 'user', 'role', 'file', and 'permissions'.
        sensitivity (float): The sensitivity level (number of standard deviations).

    Returns:
        List[Dict[str, Any]]: A list of dictionaries representing detected anomalies.
    """
    anomalies = []

    # Collect statistics on permission assignments. For simplicity, we'll focus
    # on the number of unique permissions assigned to users.
    user_permission_counts = {}
    for item in data:
        user = item.get("user")
        permissions = item.get("permissions") # Example: "rwx" for read, write, execute
        if user and permissions:
            if user not in user_permission_counts:
                user_permission_counts[user] = 0
            user_permission_counts[user] += len(permissions) # count unique permissions

    # Calculate the mean and standard deviation of permission counts
    if not user_permission_counts:
        logging.warning("No permission data available for analysis.")
        return anomalies #Return empty list

    counts = list(user_permission_counts.values())

    if len(counts) < 2:  # Need at least two data points to calculate stddev
        logging.warning("Insufficient data to calculate standard deviation.")
        return anomalies # Return empty list if there's not enough data

    mean = statistics.mean(counts)
    stdev = statistics.stdev(counts) if len(counts) > 1 else 0 # Prevent error when only one sample


    # Identify users with anomalous permission counts.
    for item in data:
        user = item.get("user")
        permissions = item.get("permissions")

        if user and permissions:
            permission_count = len(permissions)
            if stdev > 0 and (abs(permission_count - mean) > sensitivity * stdev): # Avoid division by zero
                anomalies.append({
                    "user": user,
                    "file": item.get("file"),
                    "permissions": permissions,
                    "deviation": permission_count - mean,
                    "message": f"Anomalous permissions for user {user}: {permissions} (deviation from mean: {permission_count - mean:.2f})",
                })
                logging.warning(f"Detected anomaly: User {user} - {permissions}")

    return anomalies


def save_report(report: List[Dict[str, Any]], report_file: str) -> None:
    """
    Saves the anomaly report to a JSON file.

    Args:
        report (List[Dict[str, Any]]): A list of anomaly dictionaries.
        report_file (str): The path to the output JSON file.
    """
    try:
        with open(report_file, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Anomaly report saved to: {report_file}")
    except Exception as e:
        logging.error(f"Error saving report: {e}")
        print(f"Error saving report: {e}", file=sys.stderr)


def main():
    """
    Main entry point of the pa-permission-anomaly-detector tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        # Input Validation
        if not os.path.exists(args.data_file):
            raise FileNotFoundError(f"Data file not found: {args.data_file}")

        if args.sensitivity <= 0:
            raise ValueError("Sensitivity must be a positive number.")

        data = load_permission_data(args.data_file)
        anomalies = analyze_permissions(data, args.sensitivity)
        save_report(anomalies, args.report_file)

        if anomalies:
            print(f"Detected {len(anomalies)} anomalies.  See report file: {args.report_file}")
        else:
            print("No anomalies detected.")
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON data - {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        logging.exception("An unexpected error occurred.")
        sys.exit(1)

if __name__ == "__main__":
    main()