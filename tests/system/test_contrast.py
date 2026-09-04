import math

def hex_to_rgb(hex_color):
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def luminance(r, g, b):
    a = [v / 255 for v in (r, g, b)]
    a = [v / 12.92 if v <= 0.03928 else math.pow((v + 0.055) / 1.055, 2.4) for v in a]
    return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722

def contrast_ratio(color1, color2):
    lum1 = luminance(*hex_to_rgb(color1))
    lum2 = luminance(*hex_to_rgb(color2))
    brightest = max(lum1, lum2)
    darkest = min(lum1, lum2)
    return (brightest + 0.05) / (darkest + 0.05)

def test_light_theme_contrast():
    # Light theme tokens
    bg = "#F4F7FB"
    surface = "#FFFFFF"
    secondary_surface = "#E9EFF6"
    elevated = "#F8FAFC"
    main_text = "#0F172A"
    secondary_text = "#334155"
    muted_text = "#475569"

    cyan = "#0067A3"
    teal = "#007A5E"
    amber = "#8A5A00"
    danger = "#B42318"
    purple = "#6D3ACF"

    # Background vs Text (Normal text requires 4.5:1)
    assert contrast_ratio(bg, main_text) >= 4.5
    assert contrast_ratio(surface, main_text) >= 4.5
    assert contrast_ratio(secondary_surface, main_text) >= 4.5
    assert contrast_ratio(elevated, main_text) >= 4.5

    # Background vs Secondary Text
    assert contrast_ratio(bg, secondary_text) >= 4.5

    # Background vs Muted Text
    assert contrast_ratio(bg, muted_text) >= 4.5
    assert contrast_ratio(surface, muted_text) >= 4.5

    # Large text and interface boundaries (Requires 3:1)
    assert contrast_ratio(bg, cyan) >= 3.0
    assert contrast_ratio(bg, teal) >= 3.0
    assert contrast_ratio(bg, amber) >= 3.0
    assert contrast_ratio(bg, danger) >= 3.0
    assert contrast_ratio(bg, purple) >= 3.0

def test_dark_theme_contrast():
    # Dark theme tokens
    bg = "#050E17"
    surface = "#0B1928"
    secondary_surface = "#101F30"
    elevated = "#152638"
    main_text = "#F1F5F9"
    secondary_text = "#CBD5E1"
    muted_text = "#94A3B8"

    cyan = "#19C3E6"
    teal = "#2DBE8C"
    amber = "#F0B44D"
    danger = "#F97066"
    purple = "#A678FF"

    assert contrast_ratio(bg, main_text) >= 4.5
    assert contrast_ratio(surface, main_text) >= 4.5

    assert contrast_ratio(bg, secondary_text) >= 4.5

    assert contrast_ratio(bg, muted_text) >= 4.5
    assert contrast_ratio(surface, muted_text) >= 4.5

    assert contrast_ratio(bg, cyan) >= 3.0
    assert contrast_ratio(bg, teal) >= 3.0
    assert contrast_ratio(bg, amber) >= 3.0
    assert contrast_ratio(bg, danger) >= 3.0
    assert contrast_ratio(bg, purple) >= 3.0
