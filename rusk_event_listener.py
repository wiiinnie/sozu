#!/usr/bin/env python3
import asyncio
import websockets
import httpx
import json

# --- Configuration ---
NODE_HOST = "127.0.0.1"
NODE_PORT = 8080
CONTRACT = "72883945ac1aa032a88543aacc9e358d1dfef07717094c05296ce675f23078f2"
EVENTS = ["deposit", "withdraw", "stake", "unstake", "activate", "deactivate", "slash", "reward"]
# ---------------------

async def main():
    ws_url = f"ws://{NODE_HOST}:{NODE_PORT}/on"

    print(f"Connecting to {ws_url}")
    async with websockets.connect(ws_url) as websocket:
        print("Connected to WebSocket")

        session_id = (await websocket.recv()).strip()
        print(f"Session ID: {session_id}")

        headers = {
            "Rusk-Session-Id": session_id,
        }

        async with httpx.AsyncClient(http1=True, http2=False) as http_client:
            for event in EVENTS:
                subscribe_url = f"http://{NODE_HOST}:{NODE_PORT}/on/contracts:{CONTRACT}/{event}"
                res = await http_client.get(subscribe_url, headers=headers)
                status = "OK" if res.status_code == 200 else f"FAILED ({res.status_code}: {res.text.strip()})"
                print(f"  [{event}] {status}")

        print(f"\nListening for {len(EVENTS)} events on contract {CONTRACT[:16]}...\n")

        while True:
            try:
                raw = await websocket.recv()

                if isinstance(raw, bytes) and len(raw) >= 4:
                    header_len = int.from_bytes(raw[:4], "little")
                    header_bytes = raw[4:4 + header_len]
                    payload_bytes = raw[4 + header_len:]

                    try:
                        header = json.loads(header_bytes.decode("utf-8"))
                        event_name = header.get("Content-Location", "unknown").split("/")[-1]
                    except Exception:
                        header = {}
                        event_name = "unknown"

                    print("=" * 80)
                    print(f"EVENT: {event_name.upper()}")
                    print("=" * 80)
                    print(f"\nHeader: {json.dumps(header, indent=2)}")

                    if payload_bytes:
                        print(f"\nPayload (hex):   {payload_bytes.hex()}")
                        print(f"Payload (bytes): {len(payload_bytes)} bytes")
                    print()
                else:
                    print(f"Text frame: {raw}")

            except websockets.ConnectionClosed as e:
                print(f"WebSocket closed: {e}")
                break
            except Exception as e:
                print(f"Error: {e}")
                break

if __name__ == "__main__":
    asyncio.run(main())
