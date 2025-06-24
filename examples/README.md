# BACnet Who-Is Scan Examples

This directory contains examples demonstrating BACnet device discovery using Who-Is/I-Am services.

## Examples

### whois_scan.rs
A BACnet Who-Is scanner that discovers devices on the network.

**Usage:**
```bash
cargo run --example whois_scan
```

The scanner will:
- Send Who-Is broadcast requests
- Listen for I-Am responses for 5 seconds
- Display discovered devices with their information
- Optionally send targeted Who-Is to specific devices

### responder_device.rs
A simple BACnet device that responds to Who-Is requests.

**Usage:**
```bash
cargo run --example responder_device [device_id]
```

Where `device_id` is optional (defaults to 12345).

The responder will:
- Listen on BACnet/IP port 47808
- Respond to Who-Is requests that match its device ID
- Display information about received requests and sent responses

## Testing Device Discovery

To test the Who-Is scan functionality:

1. **Start one or more responder devices in separate terminals:**
   ```bash
   # Terminal 1
   cargo run --example responder_device 12345
   
   # Terminal 2 (optional)
   cargo run --example responder_device 67890
   ```

2. **Run the scanner in another terminal:**
   ```bash
   cargo run --example whois_scan
   ```

3. **You should see the scanner discover the responder devices.**

## Automated Test

Use the provided test script to automatically test the functionality:

```bash
./test_whois_scan.sh
```

This script will:
- Start a responder device in the background
- Run the Who-Is scan
- Clean up the background process

## Network Notes

- The examples use BACnet/IP on UDP port 47808
- Broadcasts are sent to 255.255.255.255 and common local subnets
- Ensure your firewall allows UDP traffic on port 47808
- Both scanner and responder must be on the same network segment for broadcasts to work

## Troubleshooting

If devices are not discovered:
1. Check firewall settings
2. Verify both programs are running on the same network
3. Try running with elevated privileges if broadcast permissions are restricted
4. Check that no other BACnet applications are using port 47808