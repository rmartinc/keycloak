#!/usr/bin/env python

import base64
import json
import re
import sys
import unicodedata

def normalize(input_str):
    # Normalize to NFD form (Canonical Decomposition)
    nfkd_form = unicodedata.normalize('NFKD', input_str)
    # Filter out characters that are classified as combining diacritics
    return u"".join([c for c in nfkd_form if not unicodedata.combining(c)])

def write_file(name, base64_str):
    base64_str += "=" * ((4 - len(base64_str) % 4) % 4)
    try:
        with open(name, "wb") as f:
            f.write(base64.b64decode(base64_str))
    except Exception as e:
        print(f"Error in {name} {e} {base64_str}", file=sys.stderr)

def process_file(icon, short_name, flavor):
    if icon is not None:
        if icon.startswith('data:image/svg+xml;base64,'):
            base64_str = icon[26:]
            name = short_name + "-" + flavor + ".svg"
            write_file(name, base64_str)
            return name
        elif icon.startswith('data:image/png;base64,'):
            base64_str = icon[22:]
            name = short_name + "-" + flavor + ".png"
            write_file(name, base64_str)
            return name
        else:
            print("Unknown data image: " + icon, file=sys.stderr)
            return None

def stream_passkey_aaguids():
    # download the following file
    # "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json"

    names = set()
    files = {}
    output = {}
    with open("combined_aaguid.json", 'rb') as f:
        contents = json.load(f)
        try:
            for aaguid, info in contents.items():
                # Process each item here.
                # 'info' is a small dictionary for just ONE AAGUID.
                name = info.get('name')
                if (name is None):
                    continue

                short_name = normalize(name)
                short_name = re.split(r'[^0-9a-zA-Z_\-]', short_name)[0].lower()
                prefix = short_name
                i = 0
                while short_name in names:
                    i = i + 1
                    short_name = prefix + str(i)

                icon_light = info.get('icon_light')
                icon_dark = info.get('icon_dark')

                if icon_light in files:
                    file_light = files[icon_light]
                else:
                    file_light = process_file(icon_light, short_name, 'light')
                    names.add(short_name)
                    files[icon_light] = file_light

                if icon_dark in files:
                    file_dark = files[icon_dark]
                else:
                    file_dark = process_file(icon_dark, short_name, 'light')
                    names.add(short_name)
                    files[icon_dark] = file_dark

                entry = {}
                entry["name"] = name
                if (file_light is not None):
                    entry["icon_light"] = file_light
                if (file_dark is not None):
                    entry["icon_dark"] = file_dark

                output[aaguid] = entry

        except ijson.common.IncompleteJSONError:
            pass

        print(json.dumps(output, indent=2))

if __name__ == "__main__":
    stream_passkey_aaguids()