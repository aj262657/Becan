import sys
import json
import detection_engine as de

if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

def test_engine():
    with open("mock_data.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    brand = data["brand_configuration"]
    print("=== REVOLUT ENTERPRISE DRP DETECTION ENGINE VERIFICATION ===")
    for ent in data["discovered_entities"]:
        res = de.compute_composite_risk(
            entity=ent,
            official_brand=brand,
            discovered_logo_path=ent.get("logo_path"),
            official_logo_path=brand.get("logo_path")
        )
        print(f"\n[{ent['id']}] {ent['name']} ({ent['handle']})")
        print(f"  Platform: {ent['platform']}")
        print(f"  Composite Score: {res['composite_score']} / 100 [{res['severity']}]")
        print(f"  Math Components -> Text(35%): {res['math_breakdown']['components']['weighted_text']}, Logo(35%): {res['math_breakdown']['components']['weighted_logo']}, Meta(30%): {res['math_breakdown']['components']['weighted_meta']}")
        print(f"  pHash -> Off: {res['logo_forensics']['official_hash_hex']} | Disc: {res['logo_forensics']['discovered_hash_hex']} | d_H: {res['logo_forensics']['hamming_distance']} bits (Match: {res['logo_forensics']['is_match']})")
        if res['breakdown']['has_homoglyphs']:
            print(f"  Homoglyphs: {[(h['char'], h['unicode_hex'], h['replacement']) for h in res['breakdown']['detected_homoglyphs']]}")
        print(f"  Reasons:")
        for r in res['reasons']:
            print(f"    * {r}")

if __name__ == "__main__":
    test_engine()
