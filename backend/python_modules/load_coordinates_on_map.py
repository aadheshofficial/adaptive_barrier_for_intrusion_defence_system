import webbrowser

def open_coordinates_in_map(latitude : float , longitude : float) -> None:
    url = f"https://www.google.com/maps?q={latitude},{longitude}"
    webbrowser.open(url)

def help():
    help_text = (
        "\nUsage:\n"
        "    Call the function open_coordinates_in_map(latitude, longitude) with valid numerical values.\n"
        "    Example:\n"
        "        open_coordinates_in_map(37.7749, -122.4194)\n"
        "    This will open Google Maps centered at the specified coordinates.\n"
        "\nArguments:\n"
        "    latitude  (float): Latitude coordinate (e.g., 37.7749).\n"
        "    longitude (float): Longitude coordinate (e.g., -122.4194).\n"
        "\nReturns:\n"
        "    None\n"
        
    )
    return help_text
