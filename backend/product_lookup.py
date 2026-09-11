import urllib.request
import json
import re

# GS1 Country Code prefix mappings
GS1_PREFIXES = [
    (r"^0[0-9]{2}|^1[0-9]{2}", "United States / Canada"),
    (r"^3[0-7][0-9]", "France"),
    (r"^4[0-4][0-9]", "Germany"),
    (r"^4[59][0-9]", "Japan"),
    (r"^50[0-9]", "United Kingdom"),
    (r"^54[0-9]", "Belgium / Luxembourg"),
    (r"^57[0-9]", "Denmark"),
    (r"^590", "Poland"),
    (r"^64[0-9]", "Finland"),
    (r"^69[0-9]", "China"),
    (r"^70[0-9]", "Norway"),
    (r"^73[0-9]", "Sweden"),
    (r"^76[0-9]", "Switzerland"),
    (r"^80[0-9]|^81[0-9]|^82[0-9]|^83[0-9]", "Italy"),
    (r"^84[0-9]", "Spain"),
    (r"^87[0-9]", "Netherlands"),
    (r"^880", "South Korea"),
    (r"^885", "Thailand"),
    (r"^888", "Singapore"),
    (r"^890", "India"),
    (r"^90[0-9]|^91[0-9]", "Austria"),
    (r"^93[0-9]", "Australia"),
    (r"^94[0-9]", "New Zealand"),
]

def get_gs1_origin(barcode: str) -> str:
    """Returns the country of registration based on standard GS1 prefixes."""
    clean = barcode.strip()
    for pattern, country in GS1_PREFIXES:
        if re.match(pattern, clean):
            return country
    return "International / Unassigned"

def lookup_product_by_barcode(barcode: str) -> dict:
    """
    Looks up real-world product catalog information for EAN/UPC barcodes
    using free open retail databases (UPCitemdb, Open Beauty Facts, Open Food Facts).
    """
    clean_code = re.sub(r"[\s\-]+", "", (barcode or "").strip())
    result = {
        "found": False,
        "product_name": None,
        "brand": None,
        "category": None,
        "image_url": None,
        "origin_country": get_gs1_origin(clean_code),
        "quantity": None,
        "source": None,
    }

    if not clean_code or not clean_code.isdigit():
        return result

    # 1. Primary lookup: UPCitemdb (extensive coverage for electronics, cosmetics, FMCG)
    try:
        url = f"https://api.upcitemdb.com/prod/trial/lookup?upc={clean_code}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "WebVulScanner/1.0 (Security & Barcode Inspector)",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=3.5) as response:
            data = json.loads(response.read().decode("utf-8"))
            items = data.get("items", [])
            if items:
                item = items[0]
                result["found"] = True
                result["product_name"] = item.get("title")
                result["brand"] = item.get("brand")
                result["category"] = item.get("category")
                images = item.get("images", [])
                if images:
                    result["image_url"] = images[0]
                result["source"] = "UPCitemdb"
                return result
    except Exception:
        pass

    # 2. Secondary fallback: Open Facts Databases (Beauty, Food, Products)
    databases = ["openbeautyfacts", "openfoodfacts", "openproductsfacts"]
    for db in databases:
        try:
            url = f"https://world.{db}.org/api/v0/product/{clean_code}.json"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "WebVulScanner/1.0 (Security & Barcode Inspector)"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as response:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("status") == 1 and "product" in data:
                    p = data["product"]
                    name = (
                        p.get("product_name")
                        or p.get("product_name_en")
                        or p.get("generic_name")
                    )
                    if name:
                        result["found"] = True
                        result["product_name"] = name
                        result["brand"] = p.get("brands")
                        result["category"] = p.get("categories")
                        result["image_url"] = p.get("image_front_url") or p.get("image_url")
                        result["quantity"] = p.get("quantity")
                        result["source"] = db.replace("open", "Open ").title()
                        return result
        except Exception:
            continue

    return result
