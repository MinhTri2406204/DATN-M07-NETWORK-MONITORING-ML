import argparse
import asyncio
import datetime
import ipaddress
import json
import os
import platform
import re
import socket
import socketserver
import statistics
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
from collections import defaultdict, deque

import netflow
from pysnmp.hlapi.asyncio import *


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_local_env(path):
    """Load simple KEY=VALUE entries from a .env file."""
    if not os.path.isfile(path):
        return

    with open(path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if len(value) >= 2 and value[0] == value[-1]:
                if value[0] in {"'", '"'}:
                    value = value[1:-1]

            if key and key.replace("_", "").isalnum():
                os.environ.setdefault(key, value)


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


load_local_env(os.path.join(BASE_DIR, ".env"))

RAW_SNMP_DEBUG = env_bool("RAW_SNMP_DEBUG", False)
PRINT_DEVICE_SUMMARY = env_bool("PRINT_DEVICE_SUMMARY", True)
VERBOSE_PROGRESS = env_bool("VERBOSE_PROGRESS", False)
DEMO_NORMALIZE_CPU = env_bool("DEMO_NORMALIZE_CPU", False)
FLOW_DEBUG = env_bool("FLOW_DEBUG", True)
FLOW_DEBUG_LIMIT = max(1, int(os.getenv("FLOW_DEBUG_LIMIT", "100")))

POSITIVE_METRIC_MODE = os.getenv(
    "POSITIVE_METRIC_MODE", "off"
).strip().lower()
if POSITIVE_METRIC_MODE not in {"minimum_one", "all_one", "off"}:
    raise ValueError(
        "POSITIVE_METRIC_MODE must be minimum_one, all_one, or off"
    )

POST_TO_BACKEND = env_bool("POST_TO_BACKEND", True)
BACKEND_API_URL = os.getenv(
    "BACKEND_API_URL", "http://127.0.0.1:8000/api/v1"
).rstrip("/")
BACKEND_TIMEOUT_SECONDS = max(
    1.0, float(os.getenv("BACKEND_TIMEOUT_SECONDS", "10"))
)
BACKEND_API_TOKEN = os.getenv("BACKEND_API_TOKEN", "").strip()

LAB_SOURCE = os.getenv("LAB_SOURCE", "tri_lab").strip() or "tri_lab"
DATASET_LABEL = os.getenv("DATASET_LABEL", "normal").strip() or "normal"
DATASET_ATTACK_TYPE = os.getenv(
    "DATASET_ATTACK_TYPE", "none"
).strip() or "none"
DATASET_OUTPUT = os.getenv(
    "DATASET_OUTPUT", "network_dataset.json"
).strip() or "network_dataset.json"

NETFLOW_LISTEN_HOST = os.getenv("NETFLOW_LISTEN_HOST", "0.0.0.0")
NETFLOW_LISTEN_PORT = max(1, int(os.getenv("NETFLOW_LISTEN_PORT", "2055")))

INTERVAL_SECONDS = max(
    0.5, float(os.getenv("COLLECTOR_INTERVAL_SECONDS", "1"))
)
TRAFFIC_SAMPLE_DELAY = max(
    0.5, float(os.getenv("TRAFFIC_SAMPLE_DELAY", "1"))
)
SNMP_CONCURRENCY = max(1, int(os.getenv("SNMP_CONCURRENCY", "4")))

DEBUG = RAW_SNMP_DEBUG
SNMP_SEMAPHORE = asyncio.Semaphore(SNMP_CONCURRENCY)

FLOW_RECORDS = defaultdict(deque)
FLOW_RECORDS_LOCK = threading.Lock()

# Library parser templates: (exporter IP, Source ID) -> templates
NETFLOW_TEMPLATES = {}
NETFLOW_TEMPLATES_LOCK = threading.Lock()

# Fallback parser templates: (exporter IP, Source ID) -> templates
FALLBACK_V9_TEMPLATES = {}
FALLBACK_V9_LOCK = threading.Lock()

NETFLOW_SERVER = None


DEVICES = [
    {"name": "DIST", "ip": "192.168.100.10", "community": "public", "os_type": "mikrotik", "device_type": "router", "interface_name": "eth3", "flow_exporter_ip": "192.168.100.10"},
    {"name": "CORE", "ip": "10.0.2.9", "community": "public", "os_type": "mikrotik", "device_type": "router", "interface_name": "eth2", "flow_exporter_ip": "10.0.2.9"},
    {"name": "ASAv", "ip": "10.0.1.5", "community": "public", "os_type": "asa", "device_type": "firewall", "interface_name": "inside", "flow_exporter_ip": "10.0.1.5"},
    {"name": "DMZ-SERVER", "ip": "10.0.100.2", "community": "public", "os_type": "mikrotik", "device_type": "server", "interface_name": "ether3", "flow_exporter_ip": "10.0.100.2"},
    {"name": "SW", "ip": "10.0.4.1", "community": "public", "os_type": "mikrotik", "device_type": "switch", "interface_name": "bridge-lan", "flow_exporter_ip": "10.0.4.1"}
]


OIDS = {
    "common": {
        "uptime": "1.3.6.1.2.1.1.3.0",
        "ifStatus": "1.3.6.1.2.1.2.2.1.8",
    },
    "mikrotik": {
        "cpu_5min": "1.3.6.1.2.1.25.3.3.1.2",
        "mem_descr": "1.3.6.1.2.1.25.2.3.1.3",
        "mem_total": "1.3.6.1.2.1.25.2.3.1.5",
        "mem_used": "1.3.6.1.2.1.25.2.3.1.6",
        "if_in": "1.3.6.1.2.1.31.1.1.1.6",
        "if_out": "1.3.6.1.2.1.31.1.1.1.10",
    },
    "asa": {
        "cpu_5sec": "1.3.6.1.4.1.9.9.109.1.1.1.1.6",
        "cpu_1min": "1.3.6.1.4.1.9.9.109.1.1.1.1.7",
        "cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",
        "mem_name_walk": "1.3.6.1.4.1.9.9.48.1.1.1.2",
        "mem_used_base": "1.3.6.1.4.1.9.9.48.1.1.1.5",
        "mem_free_base": "1.3.6.1.4.1.9.9.48.1.1.1.6",
        "if_in": "1.3.6.1.2.1.31.1.1.1.6",
        "if_out": "1.3.6.1.2.1.31.1.1.1.10",
    },
    "ios": {
        "cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1",
        "mem_used": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
        "mem_free": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
        "if_in": "1.3.6.1.2.1.2.2.1.10",
        "if_out": "1.3.6.1.2.1.2.2.1.16",
    },
}


CPU_DEMO_RANGES = {
    "CORE": (1.0, 2.5),
    "SW": (0.8, 2.0),
    "ASAv": (1.0, 3.0),
    "DMZ-SERVER": (1.0, 3.5),
}


# NetFlow v9 standard field type -> field name.
V9_FIELD_NAMES = {
    1: "IN_BYTES",
    2: "IN_PACKETS",
    4: "PROTO",
    5: "SRC_TOS",
    6: "TCP_FLAGS",
    7: "SRC_PORT",
    8: "IPV4_SRC_ADDR",
    9: "SRC_MASK",
    10: "INPUT_SNMP",
    11: "DST_PORT",
    12: "IPV4_DST_ADDR",
    13: "DST_MASK",
    14: "OUTPUT_SNMP",
    15: "IPV4_NEXT_HOP",
    16: "SRC_AS",
    17: "DST_AS",
    21: "LAST_SWITCHED",
    22: "FIRST_SWITCHED",
    23: "OUT_BYTES",
    24: "OUT_PACKETS",
    27: "IPV6_SRC_ADDR",
    28: "IPV6_DST_ADDR",
    32: "ICMP_TYPE",
    56: "SRC_MAC",
    57: "DST_MAC",
    148: "FLOW_ID",
    231: "INITIATOR_OCTETS", 
    232: "RESPONDER_OCTETS",
    323: "EVENT_TIME_MSEC",
    333: "FW_EVENT",
}


EMPTY_FLOW_FEATURES = {
    "Flow_Duration": 0.0,
    "Flow_Packets_s": 0.0,
    "Flow_Bytes_s": 0.0,
    "Flow_IAT_Mean": 0.0,
    "Flow_IAT_Std": 0.0,
    "Fwd/Bwd_Ratio": 0.0,
    "tcp_ratio": 0.0,
    "udp_ratio": 0.0,
    "icmp_ratio": 0.0,
    "syn_ratio": 0.0,
    "unique_dst_ports": 0,
}


def safe_int(value, default=0):
    try:
        if value is None:
            return default
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        value = str(value).strip()
        if not value:
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        if value is None:
            return default
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        value = str(value).strip()
        if not value:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_positive_metric(value):
    value = safe_float(value)

    if POSITIVE_METRIC_MODE == "all_one":
        return 1.0 if value > 0 else 0.0

    if POSITIVE_METRIC_MODE == "minimum_one":
        return 1.0 if 0 < value < 1 else value

    return value


def normalize_demo_cpu(device_name, cpu_percent):
    if not DEMO_NORMALIZE_CPU or cpu_percent > 0:
        return cpu_percent, "snmp"

    low, high = CPU_DEMO_RANGES.get(device_name, (1.0, 3.0))
    steps = int((high - low) * 10)

    if steps <= 0:
        return round(low, 1), "synthetic"

    bucket = int(time.time() // max(INTERVAL_SECONDS, 1))
    name_seed = sum(ord(char) for char in device_name)
    value = low + ((bucket + name_seed) % (steps + 1)) / 10
    return round(value, 1), "synthetic"


def flow_ip_to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int.from_bytes(
                socket.inet_aton(str(value)),
                byteorder="big",
            )
        except (OSError, TypeError, ValueError):
            return 0


def post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Collector-Token": BACKEND_API_TOKEN,
        },
        method="POST",
    )

    with urllib.request.urlopen(
        request,
        timeout=BACKEND_TIMEOUT_SECONDS,
    ) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else None


def get_json(url):
    request = urllib.request.Request(
        url,
        headers={"X-Collector-Token": BACKEND_API_TOKEN},
        method="GET",
    )

    with urllib.request.urlopen(
        request,
        timeout=BACKEND_TIMEOUT_SECONDS,
    ) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else None


async def load_monitored_devices():
    if not POST_TO_BACKEND or not BACKEND_API_TOKEN:
        return DEVICES

    try:
        devices = await asyncio.to_thread(
            get_json,
            f"{BACKEND_API_URL}/collector/devices",
        )
        return DEVICES if devices is None else devices
    except Exception as error:
        print(
            f"[API_WARN] cannot load device configuration: {error}; "
            "using fallback list"
        )
        return DEVICES


async def post_metric_to_backend(record):
    bandwidth = record.get("bandwidth")
    if bandwidth is None:
        bandwidth = round(
            float(record.get("traffic_in_mbps", 0.0))
            + float(record.get("traffic_out_mbps", 0.0)),
            2,
        )

    payload = {
        "ip_address": record["ip_address"],
        "latency_ms": record["latency_ms"],
        "packet_loss_percent": record["packet_loss_percent"],
        "cpu_percent": record["cpu_percent"],
        "memory_percent": record["memory_percent"],
        "traffic_in_mbps": record["traffic_in_mbps"],
        "traffic_out_mbps": record["traffic_out_mbps"],
        "bandwidth": bandwidth,
        "bandwidth_mbps": bandwidth,
        "Flow_Duration": record["Flow_Duration"],
        "Flow_Packets_s": record["Flow_Packets_s"],
        "Flow_Bytes_s": record["Flow_Bytes_s"],
        "Flow_IAT_Mean": record["Flow_IAT_Mean"],
        "Flow_IAT_Std": record["Flow_IAT_Std"],
        "Fwd/Bwd_Ratio": record["Fwd/Bwd_Ratio"],
        "tcp_ratio": record.get("tcp_ratio", 0.0),
        "udp_ratio": record.get("udp_ratio", 0.0),
        "icmp_ratio": record.get("icmp_ratio", 0.0),
        "syn_ratio": record.get("syn_ratio", 0.0),
        "unique_dst_ports": record.get("unique_dst_ports", 0),
        "uptime_seconds": record["uptime_seconds"],
        "label": record.get("label", DATASET_LABEL),
        "attack_type": record.get("attack_type", DATASET_ATTACK_TYPE),
    }

    try:
        metric = await asyncio.to_thread(
            post_json,
            f"{BACKEND_API_URL}/metrics",
            payload,
        )
        if metric:
            print(
                f"[API] metric #{metric.get('id', '?')} "
                f"-> {record['device_name']}"
            )
    except urllib.error.HTTPError as error:
        if error.code == 404:
            print(
                f"[API_ERR] {record['device_name']} is not registered "
                "in the backend"
            )
            return
        raise


async def get_snmp_data(ip, oid, community="public", label=""):
    """Read one SNMP value; return None if the query fails."""
    async with SNMP_SEMAPHORE:
        try:
            error_indication, error_status, _, var_binds = await get_cmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                await UdpTransportTarget.create(
                    (ip, 161),
                    timeout=3,
                    retries=2,
                ),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            if error_indication or error_status:
                if DEBUG:
                    print(
                        f"[DEBUG] {ip} {label} OID={oid} "
                        f"errorIndication={error_indication} "
                        f"errorStatus={error_status}"
                    )
                return None

            for var_bind in var_binds:
                value = var_bind[1]
                if DEBUG:
                    print(
                        f"[DEBUG] {ip} {label} OID={oid} "
                        f"value={value!r} "
                        f"type={type(value).__name__}"
                    )
                if "NoSuch" in type(value).__name__:
                    return None
                return value

            return None
        except Exception as error:
            if DEBUG:
                print(
                    f"[DEBUG] {ip} {label} OID={oid} "
                    f"exception={error}"
                )
            return None


async def get_snmp_walk(ip, base_oid, community="public", label=""):
    """Walk an SNMP OID branch and return {index: value}."""
    results = {}

    async with SNMP_SEMAPHORE:
        try:
            transport = await UdpTransportTarget.create(
                (ip, 161),
                timeout=3,
                retries=2,
            )

            async for (
                error_indication,
                error_status,
                _,
                var_binds,
            ) in walk_cmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    if DEBUG:
                        print(
                            f"[DEBUG] {ip} {label} WALK {base_oid} "
                            f"errorIndication={error_indication} "
                            f"errorStatus={error_status}"
                        )
                    break

                for var_bind in var_binds:
                    index = str(var_bind[0]).split(".")[-1]
                    results[index] = var_bind[1]

            if DEBUG:
                print(
                    f"[DEBUG] {ip} {label} WALK {base_oid} "
                    f"-> {len(results)} results"
                )
        except Exception as error:
            if DEBUG:
                print(
                    f"[DEBUG] {ip} {label} WALK {base_oid} "
                    f"exception={error}"
                )

    return results


async def ping_device(ip):
    def run_ping():
        parameter = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", parameter, "4", ip]

        latency = 0.0
        packet_loss = 100.0
        status = "DOWN"

        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            status = "UP"

            if platform.system().lower() == "windows":
                loss_match = re.search(r"\((\d+)% loss", output)
                latency_match = re.search(r"Average = (\d+)ms", output)
            else:
                loss_match = re.search(r"(\d+)% packet loss", output)
                latency_match = re.search(
                    r"rtt min/avg/max/mdev = [\d.]+/(.*?)/",
                    output,
                )

            if loss_match:
                packet_loss = float(loss_match.group(1))
            if latency_match:
                latency = float(latency_match.group(1))
        except Exception:
            pass

        return status, latency, packet_loss

    return await asyncio.to_thread(run_ping)


async def get_asa_memory_index(ip, community):
    memory_names = await get_snmp_walk(
        ip,
        OIDS["asa"]["mem_name_walk"],
        community,
    )

    for index, name in memory_names.items():
        if "System memory" in str(name):
            return index

    return "1"


async def get_first_walk_number(ip, base_oid, community, label=""):
    values = await get_snmp_walk(
        ip,
        base_oid,
        community,
        label=label,
    )

    def index_key(value):
        return (0, int(value)) if str(value).isdigit() else (1, str(value))

    for index in sorted(values, key=index_key):
        value = safe_float(values[index], default=None)
        if value is not None:
            return value, index

    return None, None


async def get_interfaces_traffic_bytes(
    ip,
    community,
    os_type,
    interface_name="",
):
    statuses, in_octets, out_octets = await asyncio.gather(
        get_snmp_walk(
            ip,
            OIDS["common"]["ifStatus"],
            community,
            label="IF_STATUS",
        ),
        get_snmp_walk(
            ip,
            OIDS[os_type]["if_in"],
            community,
            label="IF_IN",
        ),
        get_snmp_walk(
            ip,
            OIDS[os_type]["if_out"],
            community,
            label="IF_OUT",
        ),
    )

    total_in = 0
    total_out = 0

    for index, status in statuses.items():
        if safe_int(status) == 1:
            total_in += safe_int(in_octets.get(index, 0))
            total_out += safe_int(out_octets.get(index, 0))

    return total_in, total_out


# ---------------------------------------------------------------------
# NetFlow v9 fallback parser
# ---------------------------------------------------------------------

def _read_v9_field_spec(payload, offset, end):
    """Read a field specifier from a v9 template."""
    if offset + 4 > end:
        return None, offset

    field_type = int.from_bytes(payload[offset:offset + 2], "big")
    field_length = int.from_bytes(payload[offset + 2:offset + 4], "big")
    offset += 4

    enterprise_number = 0

    # High bit means the field is enterprise-specific.
    if field_type & 0x8000:
        field_type &= 0x7FFF
        if offset + 4 > end:
            return None, offset

        enterprise_number = int.from_bytes(
            payload[offset:offset + 4],
            "big",
        )
        offset += 4

    if enterprise_number == 0:
        field_name = V9_FIELD_NAMES.get(
            field_type,
            f"FIELD_{field_type}",
        )
    else:
        field_name = f"PEN_{enterprise_number}_FIELD_{field_type}"

    return {
        "type": field_type,
        "length": field_length,
        "name": field_name,
        "enterprise": enterprise_number,
    }, offset


def _parse_v9_template_set(payload, offset, end, templates):
    """Parse records in a regular Template FlowSet (FlowSet ID 0)."""
    while offset + 4 <= end:
        template_id = int.from_bytes(payload[offset:offset + 2], "big")

        # Template IDs 0/1 here indicate padding or invalid trailing data.
        if template_id < 256:
            break

        field_count = int.from_bytes(
            payload[offset + 2:offset + 4],
            "big",
        )
        offset += 4

        fields = []
        for _ in range(field_count):
            field, offset = _read_v9_field_spec(
                payload,
                offset,
                end,
            )
            if field is None:
                return
            fields.append(field)

        templates[template_id] = fields


def _parse_v9_options_template_set(payload, offset, end, templates):
    """Parse Options Template FlowSet records (FlowSet ID 1)."""
    while offset + 6 <= end:
        template_id = int.from_bytes(payload[offset:offset + 2], "big")
        scope_length = int.from_bytes(
            payload[offset + 2:offset + 4],
            "big",
        )
        option_length = int.from_bytes(
            payload[offset + 4:offset + 6],
            "big",
        )
        offset += 6

        if template_id < 256:
            break

        fields_end = min(
            offset + scope_length + option_length,
            end,
        )
        fields = []

        while offset < fields_end:
            field, offset = _read_v9_field_spec(
                payload,
                offset,
                fields_end,
            )
            if field is None:
                return
            fields.append(field)

        templates[template_id] = fields

        if offset >= end:
            break


def _decode_v9_value(raw_value, field):
    """Convert a raw field value to an int, IP string, MAC string, or bytes."""
    name = field["name"]

    if name in {"IPV4_SRC_ADDR", "IPV4_DST_ADDR", "IPV4_NEXT_HOP"}:
        if len(raw_value) == 4:
            return str(ipaddress.IPv4Address(raw_value))

    if name in {"IPV6_SRC_ADDR", "IPV6_DST_ADDR"}:
        if len(raw_value) == 16:
            return str(ipaddress.IPv6Address(raw_value))

    if name in {"SRC_MAC", "DST_MAC"}:
        return ":".join(f"{byte:02x}" for byte in raw_value)

    if 0 < len(raw_value) <= 8:
        return int.from_bytes(raw_value, "big")

    return raw_value


def _read_v9_data_value(payload, offset, end, field):
    """Read a data field, including variable-length fields."""
    field_length = field["length"]

    if field_length == 65535:
        if offset >= end:
            return None, offset

        field_length = payload[offset]
        offset += 1

        if field_length == 255:
            if offset + 2 > end:
                return None, offset
            field_length = int.from_bytes(
                payload[offset:offset + 2],
                "big",
            )
            offset += 2

    if field_length < 0 or offset + field_length > end:
        return None, offset

    raw_value = payload[offset:offset + field_length]
    offset += field_length

    return _decode_v9_value(raw_value, field), offset


def _add_flow_aliases(flow):
    if "PROTO" not in flow:
        if "PROTOCOL" in flow:
            flow["PROTO"] = flow["PROTOCOL"]
        elif "IP_PROTOCOL" in flow:
            flow["PROTO"] = flow["IP_PROTOCOL"]

    if "SRC_PORT" not in flow and "L4_SRC_PORT" in flow:
        flow["SRC_PORT"] = flow["L4_SRC_PORT"]

    if "DST_PORT" not in flow and "L4_DST_PORT" in flow:
        flow["DST_PORT"] = flow["L4_DST_PORT"]

    if "IN_PACKETS" not in flow and "PACKETS" in flow:
        flow["IN_PACKETS"] = flow["PACKETS"]

    if "IN_OCTETS" not in flow:
        in_bytes_val = safe_int(
            flow.get("IN_BYTES", flow.get("BYTES", 0))
        )
        init_resp_val = (
            safe_int(flow.get("INITIATOR_OCTETS", 0))
            + safe_int(flow.get("RESPONDER_OCTETS", 0))
        )
        if in_bytes_val > 0:
            flow["IN_OCTETS"] = in_bytes_val
        elif init_resp_val > 0:
            flow["IN_OCTETS"] = init_resp_val
        elif "IN_BYTES" in flow:
            flow["IN_OCTETS"] = flow["IN_BYTES"]
        elif "BYTES" in flow:
            flow["IN_OCTETS"] = flow["BYTES"]

    if "IN_PACKETS" not in flow:
        if (
            safe_int(flow.get("IN_OCTETS", 0)) > 0
            or "FW_EVENT" in flow
            or "FIELD_233" in flow
            or safe_int(flow.get("PROTO", 0)) > 0
        ):
            flow["IN_PACKETS"] = 1

    if "OUT_OCTETS" not in flow and "OUT_BYTES" in flow:
        flow["OUT_OCTETS"] = flow["OUT_BYTES"]

    return flow


def parse_netflow_v9_fallback(payload, exporter_ip):
    """
    Parse a NetFlow v9 packet.

    Returns:
        (flows, unknown_template_ids)

    Templates are cached separately by exporter IP and Source ID.
    """
    if len(payload) < 20:
        return [], []

    if int.from_bytes(payload[0:2], "big") != 9:
        return [], []

    source_id = int.from_bytes(payload[16:20], "big")
    cache_key = (exporter_ip, source_id)
    flows = []
    unknown_template_ids = []

    with FALLBACK_V9_LOCK:
        templates = FALLBACK_V9_TEMPLATES.setdefault(cache_key, {})
        offset = 20
        packet_end = len(payload)

        while offset + 4 <= packet_end:
            flowset_id = int.from_bytes(
                payload[offset:offset + 2],
                "big",
            )
            flowset_length = int.from_bytes(
                payload[offset + 2:offset + 4],
                "big",
            )

            if flowset_length < 4:
                break

            flowset_end = offset + flowset_length
            if flowset_end > packet_end:
                break

            data_offset = offset + 4

            if flowset_id == 0:
                _parse_v9_template_set(
                    payload,
                    data_offset,
                    flowset_end,
                    templates,
                )

            elif flowset_id == 1:
                _parse_v9_options_template_set(
                    payload,
                    data_offset,
                    flowset_end,
                    templates,
                )

            elif flowset_id >= 256:
                fields = templates.get(flowset_id)

                if not fields:
                    unknown_template_ids.append(flowset_id)
                else:
                    while data_offset < flowset_end:
                        record_start = data_offset
                        record = {}
                        valid_record = True

                        for field in fields:
                            value, data_offset = _read_v9_data_value(
                                payload,
                                data_offset,
                                flowset_end,
                                field,
                            )
                            if value is None:
                                valid_record = False
                                break
                            record[field["name"]] = value

                        if not valid_record or data_offset <= record_start:
                            break

                        flows.append(_add_flow_aliases(record))

            offset = flowset_end

    return flows, unknown_template_ids


class NetFlowV9Handler(socketserver.BaseRequestHandler):
    """Receive NetFlow v9 packets and use a fallback parser if necessary."""

    def handle(self):
        payload = self.request[0]
        exporter_ip = self.client_address[0]

        if len(payload) < 20:
            if FLOW_DEBUG:
                print(
                    f"[NETFLOW_WARN] short packet from {exporter_ip}; "
                    f"length={len(payload)}"
                )
            return

        version = int.from_bytes(payload[0:2], "big")
        if version != 9:
            if FLOW_DEBUG:
                print(
                    f"[NETFLOW_WARN] ignoring version={version} "
                    f"packet from {exporter_ip}"
                )
            return

        source_id = int.from_bytes(payload[16:20], "big")
        template_key = (exporter_ip, source_id)

        # Parse independently so fallback template cache is updated even
        # when the third-party parser rejects this packet.
        fallback_flows, unknown_template_ids = (
            parse_netflow_v9_fallback(payload, exporter_ip)
        )

        # Show flow features
        if FLOW_DEBUG:
            print(
                f"[V9_PARSE] exporter={exporter_ip} "
                f"source_id={source_id} "
                f"fallback_flows={len(fallback_flows)} "
                f"missing_templates={unknown_template_ids}"
            )
        if fallback_flows:
            print(f"[V9_FIELDS] {list(fallback_flows[0].keys())}")
            print(f"[V9_SAMPLE] {fallback_flows[0]}")

        library_flows = None
        library_error = None

        try:
            with NETFLOW_TEMPLATES_LOCK:
                templates = NETFLOW_TEMPLATES.setdefault(
                    template_key,
                    {},
                )
                export = netflow.parse_packet(payload, templates)

            if getattr(export.header, "version", None) == 9:
                library_flows = [
                    flow.data
                    for flow in getattr(export, "flows", ())
                ]
        except Exception as error:
            library_error = error

        # Prefer decoded library flows; use fallback for errors or empty
        # library output when fallback successfully decoded data records.
        # if library_flows:
        #     flows = library_flows
        # else:
        #     flows = fallback_flows

        if library_flows:
            flows = [_add_flow_aliases(dict(f)) for f in library_flows]
        else:
            flows = fallback_flows

        if flows:
            received_at = time.time()

            with FLOW_RECORDS_LOCK:
                FLOW_RECORDS[exporter_ip].extend(
                    (received_at, flow)
                    for flow in flows
                )

            if library_error is not None:
                print(
                    f"[NETFLOW_V9] fallback decoded {len(flows)} flow(s) "
                    f"from {exporter_ip}; Source ID={source_id}; "
                    f"library_error={type(library_error).__name__}"
                )
            elif FLOW_DEBUG:
                print(
                    f"[NETFLOW_V9] exporter={exporter_ip} "
                    f"Source ID={source_id} flows={len(flows)}"
                )
            return

        if unknown_template_ids:
            if FLOW_DEBUG:
                missing = sorted(set(unknown_template_ids))
                print(
                    f"[NETFLOW_WAIT_TEMPLATE] exporter={exporter_ip} "
                    f"Source ID={source_id}; missing template(s)={missing}. "
                    "Waiting for the exporter to send its template."
                )
            return

        if library_error is not None and DEBUG:
            print(
                f"[NETFLOW_WARN] library and fallback parser could not "
                f"decode packet from {exporter_ip}: "
                f"{type(library_error).__name__}: {library_error}"
            )
            traceback.print_exc()


def start_netflow_listener():
    global NETFLOW_SERVER

    if NETFLOW_SERVER is not None:
        return

    try:
        NETFLOW_SERVER = socketserver.ThreadingUDPServer(
            (NETFLOW_LISTEN_HOST, NETFLOW_LISTEN_PORT),
            NetFlowV9Handler,
        )
        NETFLOW_SERVER.daemon_threads = True

        threading.Thread(
            target=NETFLOW_SERVER.serve_forever,
            daemon=True,
        ).start()

        print(
            f"[NETFLOW_V9] listening only on UDP "
            f"{NETFLOW_LISTEN_HOST}:{NETFLOW_LISTEN_PORT}"
        )
    except OSError as error:
        print(
            f"[NETFLOW_WARN] listener unavailable: {error}; "
            "flow fields will be zero"
        )


def debug_print_flow_records(exporter_ip, records, limit=10):
    print(
        f"\n[FLOW_DEBUG] exporter={exporter_ip} "
        f"total_flow_records={len(records)}"
    )

    for index, (_, flow) in enumerate(records[:limit], 1):
        protocol = safe_int(
            flow.get(
                "PROTO",
                flow.get("PROTOCOL", flow.get("IP_PROTOCOL", 0)),
            )
        )
        source_port = safe_int(
            flow.get("SRC_PORT", flow.get("L4_SRC_PORT", 0))
        )
        destination_port = safe_int(
            flow.get("DST_PORT", flow.get("L4_DST_PORT", 0))
        )

        print(
            f"  [{index}] proto={protocol} "
            f"src={flow.get('IPV4_SRC_ADDR', '')}:{source_port} "
            f"dst={flow.get('IPV4_DST_ADDR', '')}:{destination_port} "
            f"packets={safe_int(flow.get('IN_PACKETS', 0))} "
            f"bytes={safe_int(flow.get('IN_OCTETS', 0))} "
            f"first={flow.get('FIRST_SWITCHED', 0)} "
            f"last={flow.get('LAST_SWITCHED', 0)} "
            f"tcp_flags={flow.get('TCP_FLAGS', 0)}"
        )


def collect_flow_features(exporter_ip):
    with FLOW_RECORDS_LOCK:
        records = list(FLOW_RECORDS.pop(exporter_ip, ()))

    if FLOW_DEBUG and records:
        debug_print_flow_records(
            exporter_ip,
            records,
            FLOW_DEBUG_LIMIT,
        )

    if not records:
        return dict(EMPTY_FLOW_FEATURES)

    flow_items = []
    total_packets = 0
    total_bytes = 0
    forward_flows = 0
    backward_flows = 0
    protocol_counts = {1: 0, 6: 0, 17: 0}
    syn_packets = 0
    destination_ports = set()
    packet_intervals = []
    switched_times = []

    for _, flow in records:
        protocol = safe_int(
            flow.get(
                "PROTO",
                flow.get("PROTOCOL", flow.get("IP_PROTOCOL", 0)),
            )
        )
        source_port = safe_int(
            flow.get("SRC_PORT", flow.get("L4_SRC_PORT", 0))
        )
        destination_port = safe_int(
            flow.get("DST_PORT", flow.get("L4_DST_PORT", 0))
        )

        # Ignore SNMP request/response traffic.
        if protocol == 17 and (
            source_port == 161 or destination_port == 161
        ):
            continue

        packets = max(0, safe_int(flow.get("IN_PACKETS", 0)))
        octets = max(0, safe_int(flow.get("IN_OCTETS", 0)))
        first = safe_int(flow.get("FIRST_SWITCHED", 0))
        last = safe_int(flow.get("LAST_SWITCHED", 0))

        duration_ms = (last - first) % (2 ** 32)
        duration_seconds = max(duration_ms / 1000.0, 0.0)

        total_packets += packets
        total_bytes += octets
        switched_times.extend((first, last))

        if protocol in protocol_counts:
            protocol_counts[protocol] += packets

        tcp_flags = safe_int(flow.get("TCP_FLAGS", 0))
        if protocol == 6 and (tcp_flags & 0x02):
            syn_packets += packets

        if destination_port > 0:
            destination_ports.add(destination_port)

        source_ip = flow_ip_to_int(flow.get("IPV4_SRC_ADDR", 0))
        destination_ip = flow_ip_to_int(flow.get("IPV4_DST_ADDR", 0))

        if source_ip <= destination_ip:
            forward_flows += 1
        else:
            backward_flows += 1

        if packets > 1:
            packet_intervals.append(
                duration_seconds / (packets - 1)
            )

        flow_items.append({
            "duration": duration_seconds,
            "packets": packets,
            "bytes": octets,
        })

    if not flow_items:
        return dict(EMPTY_FLOW_FEATURES)

    average_duration = (
        sum(item["duration"] for item in flow_items)
        / len(flow_items)
    )

    non_zero_times = [t for t in switched_times if t > 0]
    if len(non_zero_times) >= 2:
        active_window = max(
            (max(non_zero_times) - min(non_zero_times)) % (2 ** 32) / 1000.0,
            max(float(INTERVAL_SECONDS), 1.0),
        )
    else:
        active_window = max(
            float(INTERVAL_SECONDS) + float(TRAFFIC_SAMPLE_DELAY),
            1.0,
        )

    # if switched_times:
    #     first_time = min(switched_times)
    #     last_time = max(switched_times)
    #     active_window = max(
    #         (last_time - first_time) % (2 ** 32) / 1000.0,
    #         1e-6,
    #     )
    # else:
    #     active_window = 1e-6

    tcp_packets = protocol_counts[6]
    udp_packets = protocol_counts[17]
    icmp_packets = protocol_counts[1]

    if forward_flows == 0 and backward_flows == 0:
        forward_backward_ratio = 0.0
    elif backward_flows == 0:
        forward_backward_ratio = float(forward_flows)
    else:
        forward_backward_ratio = forward_flows / backward_flows

    features = {
        "Flow_Duration": round(average_duration, 6),
        "Flow_Packets_s": round(total_packets / active_window, 6),
        "Flow_Bytes_s": round(total_bytes / active_window, 6),
        "Flow_IAT_Mean": round(
            statistics.fmean(packet_intervals)
            if packet_intervals else 0.0,
            6,
        ),
        "Flow_IAT_Std": round(
            statistics.pstdev(packet_intervals)
            if len(packet_intervals) > 1 else 0.0,
            6,
        ),
        "Fwd/Bwd_Ratio": round(forward_backward_ratio, 6),
        "tcp_ratio": round(
            min(tcp_packets / total_packets, 1.0)
            if total_packets else 0.0,
            6,
        ),
        "udp_ratio": round(
            min(udp_packets / total_packets, 1.0)
            if total_packets else 0.0,
            6,
        ),
        "icmp_ratio": round(
            min(icmp_packets / total_packets, 1.0)
            if total_packets else 0.0,
            6,
        ),
        "syn_ratio": round(
            min(syn_packets / tcp_packets, 1.0)
            if tcp_packets else 0.0,
            6,
        ),
        "unique_dst_ports": len(destination_ports),
    }

    return {
        key: normalize_positive_metric(value)
        for key, value in features.items()
    }


async def get_cpu_mem_mikrotik(ip, community):
    cpu_values, memory_descriptions, memory_totals, memory_used_values = (
        await asyncio.gather(
            get_snmp_walk(
                ip,
                OIDS["mikrotik"]["cpu_5min"],
                community,
                label="CPU",
            ),
            get_snmp_walk(
                ip,
                OIDS["mikrotik"]["mem_descr"],
                community,
                label="MEM_DESCR",
            ),
            get_snmp_walk(
                ip,
                OIDS["mikrotik"]["mem_total"],
                community,
                label="MEM_TOTAL",
            ),
            get_snmp_walk(
                ip,
                OIDS["mikrotik"]["mem_used"],
                community,
                label="MEM_USED",
            ),
        )
    )

    cpu_values = [safe_float(value) for value in cpu_values.values()]
    cpu_percent = (
        sum(cpu_values) / len(cpu_values)
        if cpu_values else 0.0
    )

    memory_indexes = [
        index
        for index, description in memory_descriptions.items()
        if "real memory" in str(description).lower()
    ]

    if not memory_indexes:
        memory_indexes = [
            index
            for index, description in memory_descriptions.items()
            if "memory" in str(description).lower()
            or "ram" in str(description).lower()
        ][:1]

    if not memory_indexes and "65536" in memory_totals:
        memory_indexes = ["65536"]

    memory_total = sum(
        safe_float(memory_totals.get(index))
        for index in memory_indexes
    )
    memory_used = sum(
        safe_float(memory_used_values.get(index))
        for index in memory_indexes
    )

    memory_percent = (
        round(memory_used / memory_total * 100, 2)
        if memory_total > 0 else 0.0
    )
    return cpu_percent, memory_percent


async def get_cpu_mem_asa(ip, community):
    cpu_percent, cpu_index = await get_first_walk_number(
        ip,
        OIDS["asa"]["cpu_5sec"],
        community,
        label="CPU_5SEC",
    )
    cpu_source = "5sec"

    if cpu_percent is None:
        cpu_percent, cpu_index = await get_first_walk_number(
            ip,
            OIDS["asa"]["cpu_1min"],
            community,
            label="CPU_1MIN",
        )
        cpu_source = "1min"

    if cpu_percent is None:
        cpu_percent, cpu_index = await get_first_walk_number(
            ip,
            OIDS["asa"]["cpu_5min"],
            community,
            label="CPU_5MIN",
        )
        cpu_source = "5min"

    if cpu_percent is None:
        print(f"[WARN] {ip} ASAv CPU unavailable; using 0.0")
        cpu_percent = 0.0
    elif PRINT_DEVICE_SUMMARY:
        print(
            f"[CPU] {ip} ASAv CPU {cpu_source} "
            f"index={cpu_index} value={cpu_percent}%"
        )

    memory_index = await get_asa_memory_index(ip, community)
    used_value, free_value = await asyncio.gather(
        get_snmp_data(
            ip,
            f"{OIDS['asa']['mem_used_base']}.{memory_index}",
            community,
            label="MEM_USED",
        ),
        get_snmp_data(
            ip,
            f"{OIDS['asa']['mem_free_base']}.{memory_index}",
            community,
            label="MEM_FREE",
        ),
    )

    memory_used = safe_float(used_value)
    memory_free = safe_float(free_value)
    memory_percent = (
        round(memory_used / (memory_used + memory_free) * 100, 2)
        if memory_used + memory_free > 0 else 0.0
    )
    return cpu_percent, memory_percent


async def get_cpu_mem_ios(ip, community):
    cpu_value, used_value, free_value = await asyncio.gather(
        get_snmp_data(
            ip,
            OIDS["ios"]["cpu_5min"],
            community,
            label="CPU",
        ),
        get_snmp_data(
            ip,
            OIDS["ios"]["mem_used"],
            community,
            label="MEM_USED",
        ),
        get_snmp_data(
            ip,
            OIDS["ios"]["mem_free"],
            community,
            label="MEM_FREE",
        ),
    )

    cpu_percent = safe_float(cpu_value)
    memory_used = safe_float(used_value)
    memory_free = safe_float(free_value)
    memory_percent = (
        round(memory_used / (memory_used + memory_free) * 100, 2)
        if memory_used + memory_free > 0 else 0.0
    )
    return cpu_percent, memory_percent


CPU_MEM_HANDLERS = {
    "mikrotik": get_cpu_mem_mikrotik,
    "asa": get_cpu_mem_asa,
    "ios": get_cpu_mem_ios,
}


async def collect_device(dev, traffic_t0, timestamp):
    ip = dev["ip"]
    community = dev["community"]
    os_type = dev["os_type"]
    name = dev["name"]
    device_type = dev["device_type"]
    interface_name = dev.get("interface_name", "")
    exporter_ip = dev.get("flow_exporter_ip", ip)

    if VERBOSE_PROGRESS:
        print(f"[*] Processing: {name} ({ip})")

    try:
        status, latency, packet_loss = await ping_device(ip)

        if status != "UP":
            flow_metrics = collect_flow_features(exporter_ip)
            record = {
                "lab_source": LAB_SOURCE,
                "device_name": name,
                "device_type": device_type,
                "ip_address": ip,
                "interface_name": interface_name,
                "status": "offline",
                "collected_at": timestamp,
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "traffic_in_mbps": 0.0,
                "traffic_out_mbps": 0.0,
                "latency_ms": latency,
                "packet_loss_percent": packet_loss,
                "bandwidth": 0.0,
                **flow_metrics,
                "uptime_seconds": 0,
                "label": DATASET_LABEL,
                "attack_type": DATASET_ATTACK_TYPE,
            }

            if PRINT_DEVICE_SUMMARY:
                print(
                    f"[OK] {name:<10} {ip:<13} "
                    f"status={record['status']:<7} "
                    f"cpu={record['cpu_percent']:>5.1f}% "
                    f"mem={record['memory_percent']:>6.2f}% "
                    f"in={record['traffic_in_mbps']:>7.2f}Mbps "
                    f"out={record['traffic_out_mbps']:>7.2f}Mbps "
                    f"loss={record['packet_loss_percent']:>5.1f}% "
                    f"uptime={record['uptime_seconds']}s"
                )
            return record

        uptime_ticks = await get_snmp_data(
            ip,
            OIDS["common"]["uptime"],
            community,
        )
        uptime_seconds = safe_float(uptime_ticks) / 100

        cpu_percent, memory_percent = await CPU_MEM_HANDLERS[os_type](
            ip,
            community,
        )
        cpu_percent, cpu_source = normalize_demo_cpu(
            name,
            cpu_percent,
        )

        in_bytes, out_bytes = await get_interfaces_traffic_bytes(
            ip,
            community,
            os_type,
            interface_name,
        )

        sample = traffic_t0.get(
            ip,
            {"in": in_bytes, "out": out_bytes, "time": time.time()},
        )
        time_delta = max(time.time() - sample["time"], 1.0)

        traffic_in_mbps = round(
            max(0, (in_bytes - sample["in"]) * 8 / time_delta / 1_000_000),
            2,
        )
        traffic_out_mbps = round(
            max(0, (out_bytes - sample["out"]) * 8 / time_delta / 1_000_000),
            2,
        )

        flow_metrics = collect_flow_features(exporter_ip)

        cpu_percent = normalize_positive_metric(cpu_percent)
        memory_percent = normalize_positive_metric(memory_percent)
        traffic_in_mbps = normalize_positive_metric(traffic_in_mbps)
        traffic_out_mbps = normalize_positive_metric(traffic_out_mbps)
        packet_loss = normalize_positive_metric(packet_loss)

        record = {
            "lab_source": LAB_SOURCE,
            "device_name": name,
            "device_type": device_type,
            "ip_address": ip,
            "interface_name": interface_name,
            "status": "online",
            "collected_at": timestamp,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "traffic_in_mbps": traffic_in_mbps,
            "traffic_out_mbps": traffic_out_mbps,
            "latency_ms": latency,
            "packet_loss_percent": packet_loss,
            "bandwidth": round(
                traffic_in_mbps + traffic_out_mbps,
                2,
            ),
            **flow_metrics,
            "uptime_seconds": round(uptime_seconds),
            "label": DATASET_LABEL,
            "attack_type": DATASET_ATTACK_TYPE,
        }

        if PRINT_DEVICE_SUMMARY:
            print(
                f"[OK] {name:<10} {ip:<13} "
                f"status={record['status']:<7} "
                f"cpu={record['cpu_percent']:>5.1f}%({cpu_source}) "
                f"mem={record['memory_percent']:>6.2f}% "
                f"in={record['traffic_in_mbps']:>7.2f}Mbps "
                f"out={record['traffic_out_mbps']:>7.2f}Mbps "
                f"loss={record['packet_loss_percent']:>5.1f}% "
                f"uptime={record['uptime_seconds']}s"
            )

        return record

    except Exception as error:
        print(f"[ERR] {name} ({ip}) collection error: {error}")
        if DEBUG:
            traceback.print_exc()
        return None


async def run_collection_cycle():
    timestamp = datetime.datetime.now(
        datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"\n=== Collection cycle: {timestamp} ===")

    devices = await load_monitored_devices()
    if not devices:
        print("[WARN] No monitored devices are available.")
        return

    traffic_results_t0 = await asyncio.gather(
        *[
            get_interfaces_traffic_bytes(
                dev["ip"],
                dev["community"],
                dev["os_type"],
                dev.get("interface_name", ""),
            )
            for dev in devices
        ]
    )

    traffic_t0 = {}
    for dev, (in_bytes, out_bytes) in zip(devices, traffic_results_t0):
        traffic_t0[dev["ip"]] = {
            "in": in_bytes,
            "out": out_bytes,
            "time": time.time(),
        }

    if VERBOSE_PROGRESS:
        print(
            f"[*] Waiting {TRAFFIC_SAMPLE_DELAY} seconds "
            "to calculate traffic rates..."
        )

    await asyncio.sleep(TRAFFIC_SAMPLE_DELAY)

    results = await asyncio.gather(
        *[
            collect_device(dev, traffic_t0, timestamp)
            for dev in devices
        ]
    )
    dataset = [record for record in results if record is not None]

    filename = DATASET_OUTPUT
    if not os.path.isabs(filename):
        filename = os.path.join(BASE_DIR, filename)

    try:
        with open(filename, "r", encoding="utf-8") as file:
            existing_data = json.load(file)
        if not isinstance(existing_data, list):
            existing_data = []
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    existing_data.extend(dataset)

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            existing_data,
            file,
            indent=4,
            ensure_ascii=False,
        )

    if POST_TO_BACKEND and dataset:
        try:
            await asyncio.gather(
                *(post_metric_to_backend(record) for record in dataset)
            )
        except Exception as error:
            print(f"[API_ERR] cannot post metrics: {error}")

    online_count = sum(
        record["status"] == "online"
        for record in dataset
    )
    print(
        f"[DONE] Added {len(dataset)} records to {filename}; "
        f"online={online_count}/{len(dataset)}"
    )


async def main_loop():
    start_netflow_listener()

    print("=== CONTINUOUS COLLECTOR STARTED (NetFlow v9 only) ===")
    print(
        f"Dataset label={DATASET_LABEL}, "
        f"attack_type={DATASET_ATTACK_TYPE}, "
        f"output={DATASET_OUTPUT}"
    )
    print("Press Ctrl+C to stop.\n")

    while True:
        await run_collection_cycle()
        print(
            f"[WAIT] Next collection in {INTERVAL_SECONDS} seconds...\n"
        )
        await asyncio.sleep(INTERVAL_SECONDS)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect network metrics and NetFlow v9 data."
    )
    parser.add_argument(
        "--label",
        choices=["normal", "abnormal"],
        default=DATASET_LABEL,
        help="Ground-truth label for this collection run.",
    )
    parser.add_argument(
        "--attack_type",
        default=DATASET_ATTACK_TYPE,
        help="Attack type label, for example none, ddos, port_scan.",
    )
    parser.add_argument(
        "--output",
        default=DATASET_OUTPUT,
        help="Dataset JSON output path.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    DATASET_LABEL = args.label
    DATASET_ATTACK_TYPE = args.attack_type
    DATASET_OUTPUT = args.output

    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("\n\n=== Collector stopped safely ===")