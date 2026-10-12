#!/usr/bin/env python3
"""Writes a 16-bit PCM WAV of a 440 Hz sine (left) and 660 Hz (right).

Usage: tone.py OUT.wav RATE CHANNELS SECONDS
"""
import math
import struct
import sys
import wave


def main():
    out, rate, channels, seconds = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
    frames = bytearray()
    for i in range(int(rate * seconds)):
        for c in range(channels):
            freq = 440 if c == 0 else 660
            frames += struct.pack("<h", int(12000 * math.sin(2 * math.pi * freq * i / rate)))
    with wave.open(out, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))


if __name__ == "__main__":
    main()
