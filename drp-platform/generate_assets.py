"""
generate_assets.py - Generates authentic enterprise PNG logo assets for Revolut Ltd
and 6 threat candidate entities for perceptual hash and visual forensics testing.
"""

import os
from PIL import Image, ImageDraw, ImageFont

ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)


def draw_revolut_official_logo(size=(256, 256)):
    """
    Authentic Revolut enterprise crest:
    Matte obsidian black background (#08080a) with clean geometric white 'R' monogram
    featuring Revolut's distinctive angled diagonal stem cut.
    """
    img = Image.new("RGB", size, (8, 8, 10))  # Ultra-deep obsidian
    draw = ImageDraw.Draw(img)
    w, h = size

    # Outer subtle rounded frame border
    draw.rounded_rectangle([w * 0.04, h * 0.04, w * 0.96, h * 0.96], radius=24, outline=(30, 35, 48), width=3)

    # Stylized Revolut "R" monogram
    # Vertical spine (left pillar) with top corner angle
    draw.rectangle([w * 0.24, h * 0.22, w * 0.38, h * 0.78], fill=(255, 255, 255))

    # Upper loop of the R
    # Top horizontal bar
    draw.rounded_rectangle([w * 0.35, h * 0.22, w * 0.74, h * 0.34], radius=4, fill=(255, 255, 255))
    # Right curved arch of upper loop
    draw.rounded_rectangle([w * 0.62, h * 0.22, w * 0.76, h * 0.52], radius=12, fill=(255, 255, 255))
    # Middle crossbar connecting back
    draw.rounded_rectangle([w * 0.35, h * 0.44, w * 0.74, h * 0.54], radius=4, fill=(255, 255, 255))
    # Inner cutout for the loop
    draw.rounded_rectangle([w * 0.38, h * 0.32, w * 0.64, h * 0.44], radius=4, fill=(8, 8, 10))

    # Distinctive diagonal leg of the R
    leg_points = [
        (w * 0.48, h * 0.50),
        (w * 0.62, h * 0.50),
        (w * 0.78, h * 0.78),
        (w * 0.62, h * 0.78),
    ]
    draw.polygon(leg_points, fill=(255, 255, 255))

    # Subtle cyan accent pip in top right
    draw.ellipse([w * 0.78, h * 0.18, w * 0.84, h * 0.24], fill=(0, 212, 255))

    return img


def draw_revolut_support_logo(official_img):
    """
    Typosquat attacker copied official logo and overlaid a high-contrast
    red '24/7 SUPPORT' urgency badge.
    """
    img = official_img.copy()
    draw = ImageDraw.Draw(img)
    w, h = img.size
    # Red urgency footer banner
    draw.rounded_rectangle([w * 0.08, h * 0.80, w * 0.92, h * 0.94], radius=6, fill=(220, 38, 38))
    # Inner warning bar
    draw.rounded_rectangle([w * 0.15, h * 0.84, w * 0.85, h * 0.90], radius=3, fill=(254, 226, 226))
    return img


def draw_revolut_homoglyph_logo(official_img):
    """Near pixel-identical cloned logo used by Cyrillic Telegram impersonator."""
    img = official_img.copy()
    return img


def draw_revolut_cash_logo():
    """Rogue mobile app logo: Dark card with green/gold money badges and fake loan aesthetic."""
    img = Image.new("RGB", (256, 256), (12, 20, 16))
    draw = ImageDraw.Draw(img)
    w, h = 256, 256

    # Emerald border
    draw.rounded_rectangle([w * 0.05, h * 0.05, w * 0.95, h * 0.95], radius=24, outline=(16, 185, 129), width=4)

    # Mimic white R
    draw.rectangle([w * 0.22, h * 0.22, w * 0.34, h * 0.74], fill=(240, 253, 244))
    draw.rounded_rectangle([w * 0.32, h * 0.22, w * 0.68, h * 0.50], radius=8, fill=(240, 253, 244))
    draw.rounded_rectangle([w * 0.34, h * 0.30, w * 0.58, h * 0.42], radius=4, fill=(12, 20, 16))
    draw.polygon([(w * 0.44, h * 0.48), (w * 0.58, h * 0.48), (w * 0.72, h * 0.74), (w * 0.58, h * 0.74)], fill=(240, 253, 244))

    # Prominent Gold Dollar badge overlay
    draw.ellipse([w * 0.60, h * 0.58, w * 0.92, h * 0.90], fill=(234, 179, 8), outline=(254, 240, 138), width=3)
    draw.rectangle([w * 0.74, h * 0.64, w * 0.78, h * 0.84], fill=(15, 23, 42))
    draw.rounded_rectangle([w * 0.68, h * 0.68, w * 0.84, h * 0.80], radius=3, fill=(15, 23, 42))

    return img


def draw_revolut_fan_logo():
    """Community fan forum logo: Indigo/violet gradient with custom heart/star pin."""
    img = Image.new("RGB", (256, 256), (49, 46, 129))  # Indigo
    draw = ImageDraw.Draw(img)
    w, h = 256, 256

    draw.rounded_rectangle([w * 0.06, h * 0.06, w * 0.94, h * 0.94], radius=24, outline=(129, 140, 248), width=3)
    # Circular emblem
    draw.ellipse([w * 0.18, h * 0.18, w * 0.82, h * 0.82], fill=(67, 56, 202))
    # Heart center
    draw.ellipse([w * 0.32, h * 0.34, w * 0.52, h * 0.54], fill=(244, 114, 182))
    draw.ellipse([w * 0.48, h * 0.34, w * 0.68, h * 0.54], fill=(244, 114, 182))
    draw.polygon([(w * 0.32, h * 0.45), (w * 0.68, h * 0.45), (w * 0.50, h * 0.72)], fill=(244, 114, 182))

    return img


def draw_revolut_detailing_logo():
    """Benign auto detailing logo: Blue slate with sports car silhouette and buffer wave."""
    img = Image.new("RGB", (256, 256), (15, 30, 48))
    draw = ImageDraw.Draw(img)
    w, h = 256, 256

    draw.rounded_rectangle([w * 0.06, h * 0.06, w * 0.94, h * 0.94], radius=20, outline=(56, 189, 248), width=2)
    # Car roof curve
    draw.arc([w * 0.20, h * 0.25, w * 0.80, h * 0.65], start=180, end=360, fill=(255, 255, 255), width=8)
    # Car body lower
    draw.rounded_rectangle([w * 0.12, h * 0.50, w * 0.88, h * 0.68], radius=8, fill=(14, 165, 233))
    # Wheels
    draw.ellipse([w * 0.22, h * 0.60, w * 0.38, h * 0.76], fill=(15, 23, 42), outline=(255, 255, 255), width=3)
    draw.ellipse([w * 0.62, h * 0.60, w * 0.78, h * 0.76], fill=(15, 23, 42), outline=(255, 255, 255), width=3)
    # Sparkle / Polish shine
    draw.polygon([(w * 0.70, h * 0.22), (w * 0.75, h * 0.30), (w * 0.70, h * 0.38), (w * 0.65, h * 0.30)], fill=(254, 240, 138))

    return img


def generate_all_assets():
    official = draw_revolut_official_logo()
    official.save(os.path.join(ASSETS_DIR, "revolut_official_logo.png"))

    support = draw_revolut_support_logo(official)
    support.save(os.path.join(ASSETS_DIR, "revolut_support_logo.png"))

    homoglyph = draw_revolut_homoglyph_logo(official)
    homoglyph.save(os.path.join(ASSETS_DIR, "revolut_homoglyph_logo.png"))

    cash = draw_revolut_cash_logo()
    cash.save(os.path.join(ASSETS_DIR, "revolut_cash_logo.png"))

    fan = draw_revolut_fan_logo()
    fan.save(os.path.join(ASSETS_DIR, "revolut_fan_logo.png"))

    detailing = draw_revolut_detailing_logo()
    detailing.save(os.path.join(ASSETS_DIR, "revolut_detailing_logo.png"))

    print("All enterprise Revolut assets successfully created in", ASSETS_DIR)


if __name__ == "__main__":
    generate_all_assets()
