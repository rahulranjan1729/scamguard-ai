import wave
import math
import struct
import subprocess
from pathlib import Path

def generate_lofi_track(filename="lofi_background.wav", duration_sec=35, sample_rate=44100):
    bpm = 100
    sec_per_beat = 60.0 / bpm
    total_samples = int(duration_sec * sample_rate)
    
    # Chord frequencies (Hz) for upbeat lo-fi progression: Cmaj7 -> Am7 -> Fmaj7 -> G7
    chords = [
        [261.63, 329.63, 392.00, 493.88], # Cmaj7
        [220.00, 261.63, 329.63, 392.00], # Am7
        [174.61, 220.00, 261.63, 329.63], # Fmaj7
        [196.00, 246.94, 293.66, 349.23], # G7
    ]

    audio_bytes = bytearray()

    for i in range(total_samples):
        t = i / sample_rate
        beat = t / sec_per_beat
        measure = int(beat / 4)
        chord_idx = measure % len(chords)
        current_chord = chords[chord_idx]

        # 1. Warm Synth Chords (Soft sine harmonics)
        chord_val = 0.0
        for freq in current_chord:
            # Soft attack envelope
            beat_phase = (beat % 4) / 4.0
            env = math.exp(-1.5 * beat_phase) * 0.12
            chord_val += math.sin(2 * math.pi * freq * t) * env
            # Add subtle second harmonic for warmth
            chord_val += math.sin(2 * math.pi * freq * 2 * t) * (env * 0.3)

        # 2. Upbeat Bassline
        bass_freq = current_chord[0] / 2.0
        bass_env = math.exp(-2.0 * ((beat % 1))) * 0.25
        bass_val = math.sin(2 * math.pi * bass_freq * t) * bass_env

        # 3. Soft Lo-Fi Kick Drum (Beats 1 & 3)
        beat_in_measure = beat % 4
        kick_env1 = math.exp(-12.0 * (beat_in_measure - 0)) if beat_in_measure >= 0 else 0
        kick_env3 = math.exp(-12.0 * (beat_in_measure - 2)) if beat_in_measure >= 2 else 0
        kick_env = max(kick_env1, kick_env3)
        kick_freq = 60 * math.exp(-10.0 * (beat_in_measure % 2))
        kick_val = math.sin(2 * math.pi * kick_freq * t) * kick_env * 0.35 if kick_env > 0.01 else 0

        # 4. Crisp Lo-Fi Snare/Rimshot (Beats 2 & 4)
        snare_env2 = math.exp(-15.0 * (beat_in_measure - 1)) if beat_in_measure >= 1 else 0
        snare_env4 = math.exp(-15.0 * (beat_in_measure - 3)) if beat_in_measure >= 3 else 0
        snare_env = max(snare_env2, snare_env4)
        snare_val = (math.sin(2 * math.pi * 200 * t) + (math.sin(2 * math.pi * 800 * t) * 0.5)) * snare_env * 0.25 if snare_env > 0.01 else 0

        # Combine all components
        sample = (chord_val + bass_val + kick_val + snare_val) * 0.6
        # Clamp sample
        sample = max(-1.0, min(1.0, sample))

        # Convert to 16-bit PCM integer
        int_sample = int(sample * 32767)
        audio_bytes.extend(struct.pack('<h', int_sample))

    # Write WAV file
    with wave.open(filename, 'wb') as wav_file:
        wav_file.setnchannels(1) # Mono
        wav_file.setsampwidth(2) # 16-bit
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(audio_bytes)

    print(f"Generated upbeat lo-fi audio track: {filename}")

if __name__ == "__main__":
    generate_lofi_track()
