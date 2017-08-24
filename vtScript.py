import argparse
import requests
import pprint
import sys


def parse_params():
    """Pull the necessary parameters to fetch file data from command line arguments

    Returns:
         str: The user's TotalVirus API key
         str: The type of file hash to check - either md5 or sha256
         str: The file's md5 or sha256 hash
    """
    parser = argparse.ArgumentParser(description="Obtains TotalVirus analysis of a file based on md5 or sha256 key")
    parser.add_argument("-a", "--api-key", default="", help="User's TotalVirus API key", required=True)
    parser.add_argument("-r", "--resource-type", default="",
                        help="Type of file hash - either md5 or sha256", required=False)
    parser.add_argument("-s", "--hash", default="", help="The md5 or sha256 hash of the file to test", required=True)

    args = parser.parse_args()

    return args.api_key, args.resource_type, args.hash


def request_file_scan_report(api_key, resource_type, hash_key):
    """Requests a file scan report from TotalVirus

    Args:
        api_key (str): The user's TotalVirus API key
        resource_type (str): The type of file hash to check - either md5 or sha256
        hash_key (str): The file's md5 or sha256 hash

    Returns:
        dict: Parsed JSON response from the request
    """
    try:
        response = requests.get("https://www.virustotal.com/vtapi/v2/file/report",
                                params={"apikey": api_key, "resource": hash_key})
        # Allow the built-in raise_for_status to handle status-code checking easily
        response.raise_for_status()
    except requests.RequestException as e:
        print("Failed to fetch file scan report: " + str(e))
        sys.exit(1)

    return response.json()


def remap_file_scan_report(scan_report):
    """Remaps the file scan report from TotalVirus to a preferred layout

    Args:
        scan_report (dict): Response from a TotalVirus file scan report request, parsed from JSON

    Returns:
        dict: Remapped report, based on the provided scan report
    """
    # The new report, mapped from the original
    report = {"data": {}, "alertType": "virusTotal", "alertDescription": "VT File Scan results"}
    report["data"]["md5"] = scan_report["md5"]
    report["data"]["sha256"] = scan_report["sha256"]
    report["data"]["scanData"] = scan_report["scan_date"]
    report["data"]["scanPositives"] = scan_report["positives"]
    report["data"]["avVendorDetect"] = scan_report["scans"]["Symantec"]["detected"]
    report["data"]["originalAlertURL"] = scan_report["permalink"]

    return report


def main():
    """Uses command-line arguments to make a file scan report request to TotalVirus, maps the result to a preferred
        layout, and prints it to the terminal. This function is used primarily to prevent variables from leaking into
        the outer scope from the [__name__ == "__main__"] section.
    """
    api_key, resource_type, hash_key = parse_params()
    file_scan_report = request_file_scan_report(api_key, resource_type, hash_key)
    mapped_report = remap_file_scan_report(file_scan_report)

    pprint.pprint(mapped_report, indent=4)

if __name__ == "__main__":
    main()
