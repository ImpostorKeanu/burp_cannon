# Burp Cannon

Replay requests parsed from an XML file of Burp items through an upstream proxy. Useful when identifying function level access control flaws.

# Usage

1. Save desired items from burp by selecting them in the `Target` tab and then `Save selected items`
2. Open a new burp instance and attain an authenticated context
3. Execute `cannon.py` such that it uses the latest Burp instance as the proxy

# Help

Use the `--help` flag for more information.
