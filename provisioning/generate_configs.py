import os
import yaml
from jinja2 import Environment, FileSystemLoader

INVENTORY_FILE = "provisioning/day0_inventory.yml"
TEMPLATE_DIR = "provisioning"
TEMPLATE_FILE = "srl_base.j2"
OUTPUT_DIR = "configs"


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    template = env.get_template(TEMPLATE_FILE)

    with open(INVENTORY_FILE, "r", encoding="utf-8") as file:
        inventory = yaml.safe_load(file)

    if not inventory or "switches" not in inventory:
        raise ValueError(
            f"Inventory file {INVENTORY_FILE} does not contain 'switches'"
        )

    print(f"Generating Day-0 configurations in {OUTPUT_DIR}/")

    for hostname, data in inventory["switches"].items():

        config_content = template.render(
            hostname=hostname,
            router_id=data["router_id"],
            interfaces=data.get("interfaces", {}),
            vlan_interfaces=data.get("vlan_interfaces", []),
        )

        output_file = os.path.join(
            OUTPUT_DIR,
            f"{hostname}.cfg"
        )

        with open(output_file, "w", encoding="utf-8") as file:
            file.write(config_content)

        print(f"  [+] Created: {output_file}")

    print()
    print("Generation complete.")


if __name__ == "__main__":
    main()