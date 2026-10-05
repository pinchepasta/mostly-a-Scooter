# mostly-a-Scooter (reconnect-fix mod)

Build and flash (Cardputer ADV connected over USB):

    pip install platformio
    pio run -t upload
    pio device monitor        # 115200 baud, for logs

Changes vs. upstream (src/main.cpp, marked "MOD"):
- linkUpRetry(): patient reconnect with advertising check (6 tries)
- 4 s BLE supervision timeout (setConnectionParams(24,40,0,400))
- initial connect gets 2 extra attempts
- WiFi forced off before reconnecting

Added: meters page on the ride screen (key 2): g-force, IMU tilt, speed, battery amps (see README).
