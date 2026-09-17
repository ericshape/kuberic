import json
import pathlib
import re
import sys
import textwrap


def main():
    crd = json.load(sys.stdin)
    properties = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
    path = pathlib.Path(__file__).resolve().parents[1] / "kuberic-operator/deploy/deployment.yaml"
    text = path.read_text()
    for section, field, marker in (
        ("spec", "managed", "managed-services-spec"),
        ("status", "managedServices", "managed-services-status"),
    ):
        schema = properties[section]["properties"][field]
        indent = " " * 14
        block = (
            f"{indent}# BEGIN GENERATED {marker}\n"
            f"{indent}{field}:\n"
            + textwrap.indent(json.dumps(schema, indent=2, ensure_ascii=True), indent + "  ")
            + f"\n{indent}# END GENERATED {marker}"
        )
        pattern = rf"(?m)^{indent}# BEGIN GENERATED {marker}\n[\s\S]*?^{indent}# END GENERATED {marker}"
        text, count = re.subn(pattern, lambda _: block, text)
        if count != 1:
            raise SystemExit(f"Expected exactly one {marker} block in {path}, found {count}")
    path.write_text(text)


if __name__ == "__main__":
    main()
