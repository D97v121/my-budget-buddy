def usd(value):
    return f"${value:,.2f}"

def timestamp_editor(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")
