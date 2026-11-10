# manufacturer_loader.py
# Copyright (c) 2026, Vincent Demanet
#
# Licensed under the EUPL, Version 1.2 or - as soon they will be approved
# by the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
#
#     https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the Licence is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the Licence for the specific language governing permissions and
# limitations under the Licence.


import yaml
import os
import json

def load_manufacturer_ids(yaml_path="company_identifiers.yaml"):
    """Load Bluetooth manufacturer IDs from YAML into a dict."""
    if not os.path.exists(yaml_path):
        raise FileNotFoundError(f"YAML file not found: {yaml_path}")
    
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    company_list = data.get("company_identifiers", [])

    manufacturer_dict = {}
    for item in company_list:
        value = item.get("value")
        name = item.get("name", "Unknown")

        # Handle both string "0x004C" and integer 0x004C
        if isinstance(value, str):
            try:
                value_int = int(value, 16)
            except ValueError:
                continue
        elif isinstance(value, int):
            value_int = value
        else:
            continue

        manufacturer_dict[value_int] = name

    return manufacturer_dict

def load_manufacturer_ids_json(json_path="company_identifiers.json"):
    """Load Bluetooth manufacturer IDs from JSON into a dict."""
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"JSON file not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Your JSON structure stores entries under "_default"
    entries = data.get("_default", {})

    manufacturer_dict = {}

    for item in entries.values():
        value = item.get("id")
        name = item.get("mfg", "Unknown")

        # Expect hex string like "0x004C"
        if isinstance(value, str):
            try:
                value_int = int(value, 16)
            except ValueError:
                continue
        elif isinstance(value, int):
            value_int = value
        else:
            continue

        manufacturer_dict[value_int] = name

    return manufacturer_dict

def load_manufacturer_ids_company_ids(json_path="company_ids.json"):
    """Load Bluetooth manufacturer IDs from company_ids.json into a dict.
    
    Expects a JSON array of objects with 'code' and 'name' fields.
    Returns a dict mapping integer code -> company name.
    """
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"JSON file not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    manufacturer_dict = {}
    for item in data:
        code = item.get("code")
        name = item.get("name", "Unknown")

        # Handle both integer and hex-string codes
        if isinstance(code, str):
            try:
                code_int = int(code, 0)  # auto-detect base (0x prefix or plain)
            except ValueError:
                continue
        elif isinstance(code, int):
            code_int = code
        else:
            continue

        manufacturer_dict[code_int] = name

    return manufacturer_dict
