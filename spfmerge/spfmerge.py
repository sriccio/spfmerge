import sys
import argparse
import re
from fqdn import FQDN
from collections import OrderedDict
from ipaddress import (
    ip_address,
    ip_network,
    IPv4Network,
    IPv4Address,
    IPv6Network,
    IPv6Address,
)


def _is_fqdn(value):
    """Check if value is a valid FQDN"""
    return FQDN(value).is_valid


def _is_ipv4(value):
    """Check if value is a valid IPv4 Network or address"""
    try:
        return type(ip_network(value)) == IPv4Network or type(
            ip_address(value) == IPv4Address
        )
    except ValueError:
        return False


def _is_ipv6(value):
    """Check if value is a valid IPv6 Network or address"""
    try:
        return type(ip_network(value)) == IPv6Network or type(
            ip_address(value) == IPv6Address
        )
    except ValueError:
        return False


class SPFRecord(object):
    # noinspection SpellCheckingInspection
    SPF_SYNTAX_REGEX_STRING = r"^v=spf1( +([-+?~]?(all|include:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]" \
                              r"|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A" \
                              r"-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})" \
                              r"|a(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|" \
                              r"%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhil" \
                              r"opr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?" \
                              r"(\/\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|mx(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0" \
                              r"-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z](" \
                              r"[-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[" \
                              r"0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?(\/\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0" \
                              r"-8]))?)?|ptr(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/" \
                              r"=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHIL" \
                              r"OPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?|ip4:([0-9]|[1-" \
                              r"9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-" \
                              r"5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[" \
                              r"0-4][0-9]|25[0-5])(\/([0-9]|1[0-9]|2[0-9]|3[0-2]))?|ip6:(::|([0-9A-Fa-f]{1,4}:){7}[0-" \
                              r"9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,8}:|([0-9A-Fa-f]{1,4}:){7}:[0-9A-Fa-f]{1,4}|([0-9" \
                              r"A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1" \
                              r",3}|([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f" \
                              r"]{1,4}){1,5}|([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,6}|[0-9A-Fa-f]{1,4}:(:[0-9A-" \
                              r"Fa-f]{1,4}){1,7}|:(:[0-9A-Fa-f]{1,4}){1,8}|([0-9A-Fa-f]{1,4}:){6}([0-9]|[1-9][0-9]|1[" \
                              r"0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9" \
                              r"]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|" \
                              r"25[0-5])|([0-9A-Fa-f]{1,4}:){6}:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0" \
                              r"-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9" \
                              r"]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){5}:(" \
                              r"[0-9A-Fa-f]{1,4}:)?([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9" \
                              r"]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(" \
                              r"[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1" \
                              r",4}:){0,2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{" \
                              r"2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-" \
                              r"9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3" \
                              r"}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]" \
                              r"[0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1" \
                              r"[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}([0-9]|[" \
                              r"1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[" \
                              r"0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|" \
                              r"2[0-4][0-9]|25[0-5])|[0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}([0-9]|[1-9][0-9]|1[0-" \
                              r"9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|" \
                              r"[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25" \
                              r"[0-5])|::([0-9A-Fa-f]{1,4}:){0,6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([" \
                              r"0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-" \
                              r"9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(\d{1,2}|10[0-9]|11[" \
                              r"0-9]|12[0-8]))?|exists:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]" \
                              r")?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|" \
                              r"%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))|redire" \
                              r"ct=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%" \
                              r"_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilo" \
                              r"pr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|exp=(%\{[CDHILOPR-Tcdhilopr" \
                              r"-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z" \
                              r"]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|" \
                              r"11[0-9]|12[0-8])?r?[+-\/=_]*\})|[A-Za-z][-.0-9A-Z_a-z]*=(%\{[CDHILOPR-Tcdhilopr-t]([1" \
                              r"-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*))* *$"

    SPF_SYNTAX_REGEX = re.compile(SPF_SYNTAX_REGEX_STRING, re.IGNORECASE)

    def __init__(self, txt):
        self.txt = txt
        self.is_valid = self._check_txt_syntax()
        self.version = None
        self.mechanisms = OrderedDict()
        self.mechanisms["a"] = list()
        self.mechanisms["mx"] = [{"qualifier": "+", "value": False}]
        self.mechanisms["ip4"] = list()
        self.mechanisms["ip6"] = list()
        self.mechanisms["include"] = list()
        self.mechanisms["all"] = [{"qualifier": "-", "value": True}]
        self._parse_txt(self.txt)

    def _check_txt_syntax(self):
        if not self.SPF_SYNTAX_REGEX.match(self.txt):
            return False
        return True

    def generate_txt(self):
        txt = f"v={self.version}"
        for mechanism_name, mecanism_entries in self.mechanisms.items():
            for mechanism_entry in mecanism_entries:
                # Strip + qualifier as is the default
                if mechanism_entry["qualifier"] == "+":
                    mechanism_entry["qualifier"] = ""

                if (
                    mechanism_entry["value"]
                    and type(mechanism_entry["value"]) == str
                ):
                    txt = f"{txt} {mechanism_entry['qualifier']}{mechanism_name}:{mechanism_entry['value']}"
                else:
                    txt = f"{txt} {mechanism_entry['qualifier']}{mechanism_name}"
        return txt

    def _parse_txt(self, txt):
        """Parses the raw TXT record"""
        for entry in txt.split(" "):
            # Determine qualifier
            qualifier = "+"
            if entry[0] in "+~-?":
                qualifier = entry[0]
                entry = entry[1:]

            if entry.startswith("v") and "=" in entry:
                self._add_version(entry)
            elif entry.startswith("include") and ":" in entry:
                self._add_include(entry, qualifier)
            elif entry.startswith("redirect") and "=" in entry:
                self._add_redirect(entry, qualifier)
            elif entry.startswith("ip4") and ":" in entry:
                self._add_ip4(entry, qualifier)
            elif entry.startswith("ip6") and ":" in entry:
                self._add_ip6(entry, qualifier)
            elif entry.startswith("a") and ":" in entry:
                self._add_a(entry, qualifier)
            elif entry == "a":
                self._add_a("", qualifier)
            elif entry == "mx":
                self._add_mx(qualifier)
            elif entry == "all":
                self._add_all(qualifier)
            else:
                print(f"Unknown SPF mechanism '{entry}'")

    def _add_version(self, entry):
        value = entry.split("=", 1)[1]
        if value != "spf1":
            print(
                f"SKIPPED: '{value}' is not a valid SPF version. The only valid version is 'spf1'"
            )
            return False
        self.version = value

    def _add_include(self, entry, qualifier):
        value = entry.split(":", 1)[1]
        if not _is_fqdn(value):
            print(f"SKIPPED: '{value}' is not a valid FQDN.")
            return False

        self.mechanisms["include"].append({"qualifier": qualifier, "value": value})

    def _add_redirect(self, entry, qualifier):
        self.mechanisms["redirects"].append(
            {"qualifier": qualifier, "value": entry.split("=", 1)[1].strip('"')}
        )

    def _add_ip4(self, entry, qualifier):
        value = entry.split(":", 1)[1]
        if not _is_ipv4(value):
            print(f"SKIPPED: '{value}' is not a valid IPv4 CIDR or address.")
            return False

        self.mechanisms["ip4"].append({"qualifier": qualifier, "value": value})

    def _add_ip6(self, entry, qualifier):
        value = entry.split(":", 1)[1]
        if not _is_ipv6(value):
            print(f"SKIPPED: '{value}' is not a valid IPv6 CIDR or address.")
            return False

        self.mechanisms["ip6"].append({"qualifier": qualifier, "value": value})

    def _add_a(self, entry, qualifier):
        value = False
        if len(entry) > 1:
            value = entry.split(":", 1)[1]
            if not _is_fqdn(value):
                print(f"SKIPPED: '{value}' is not a valid FQDN.")
                return False

        self.mechanisms["a"].append({"qualifier": qualifier, "value": value})

    def _add_mx(self, qualifier):
        self.mechanisms["mx"][0] = {"qualifier": qualifier, "value": True}

    def _add_all(self, qualifier):
        self.mechanisms["all"][0] = {"qualifier": qualifier, "value": True}


def process_args(args):
    #
    # Command-line parser logic
    #
    parser = argparse.ArgumentParser(
        description="spf-appender.py - Merge elements from two existing SPF TXT records"
    )

    # global options
    parser.add_argument(
        "primary_spf", metavar="primary_spf", type=str, help="Primary SPF string"
    )
    parser.add_argument(
        "secondary_spf",
        metavar="secondary_spf",
        type=str,
        help="Secondary SPF string to be merged",
    )

    parsed_args = parser.parse_args(args)

    return parsed_args


def cli(args=None):
    # Parse arguments
    if not args:
        args = sys.argv[1:]
    parsed_args = process_args(args)

    # Some sanity stuff
    primary_spf = parsed_args.primary_spf.lower()
    secondary_spf = parsed_args.secondary_spf.lower()

    # Parse original SPF
    original_spf_object = SPFRecord(primary_spf)
    if not original_spf_object.is_valid:
        print("FATAL: Original SPF TXT is not matching a valid SPF syntax. Abort!")
        exit(1)

    # Parse secondary SPF
    secondary_spf_object = SPFRecord(secondary_spf)
    if not secondary_spf_object.is_valid:
        print("FATAL: Secondary TXT value is not matching a valid SPF syntax. Abort!")
        exit(1)

    """
    print(original_spf_object.is_valid)
    print(original_spf_object.version)
    for mechanism in original_spf_object.mechanisms:
        print(f"{mechanism}: {original_spf_object.mechanisms[mechanism]}")

    # Parse
    print(secondary_spf_object.is_valid)
    print(secondary_spf_object.version)
    for mechanism in secondary_spf_object.mechanisms:
        print(f"{mechanism}: {secondary_spf_object.mechanisms[mechanism]}")
    """

    print(original_spf_object.generate_txt())
    print(secondary_spf_object.generate_txt())
