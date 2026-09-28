import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from playwright.async_api import async_playwright

ARTIFACT_DIR = Path("/config/.gemini/antigravity/brain/dceabe07-0ddb-4539-bd22-3825a5ccc6f7")
VIDEO_TMP_DIR = Path("/tmp/playwright_videos_livecall")

async def record_demo():
    if VIDEO_TMP_DIR.exists():
        shutil.rmtree(VIDEO_TMP_DIR)
    VIDEO_TMP_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 720},
            record_video_dir=str(VIDEO_TMP_DIR),
            record_video_size={"width": 1280, "height": 720}
        )
        page = await context.new_page()

        print("Navigating to live ScamGuard AI frontend...")
        await page.goto("https://scamguard-frontend-795324405772.us-east1.run.app", wait_until="networkidle")
        await asyncio.sleep(2)

        # --- Scene 1: Live Call Sentinel Protection & Caregiver Alert ---
        prompt1 = '🚨 LIVE CALL TRANSCRIPT: "Hello sir, this is Officer Davis from Social Security Dept. Your SSN is suspended. You must immediately buy $500 in Target gift cards and give me the codes or police will arrest you in 30 minutes!"'
        print(f"Sending Live Call Prompt 1: {prompt1}")
        await page.fill("#input", prompt1)
        await asyncio.sleep(1)
        await page.click("button:has-text('Send')")

        print("Waiting for response 1 (Live call analysis & guardian notification)...")
        await page.wait_for_function(
            "() => { const bubbles = document.querySelectorAll('.msg.agent .bubble'); return bubbles.length > 0 && bubbles[bubbles.length - 1].textContent.trim() !== '…'; }",
            timeout=40000
        )
        await asyncio.sleep(5)

        # --- Scene 2: Omni Model Video Generation for Threat Warning ---
        prompt2 = "🎬 Generate a 3-second animated threat warning video clip for a Gift Card Social Security Scam"
        print(f"Sending Prompt 2 (Omni Video Generation): {prompt2}")
        await page.fill("#input", prompt2)
        await asyncio.sleep(1)
        await page.click("button:has-text('Send')")

        print("Waiting for response 2 (Omni model video generation)...")
        await page.wait_for_function(
            "() => { const bubbles = document.querySelectorAll('.msg.agent .bubble'); return bubbles.length > 1 && bubbles[bubbles.length - 1].textContent.trim() !== '…'; }",
            timeout=60000
        )
        await asyncio.sleep(6)

        # Save video path
        video_obj = page.video
        video_path = await video_obj.path() if video_obj else None
        
        await context.close()
        await browser.close()
        print(f"Recorded video saved to: {video_path}")

        if video_path and os.path.exists(video_path):
            output_mp4 = ARTIFACT_DIR / "scamguard_live_call_demo.mp4"
            output_webm = ARTIFACT_DIR / "scamguard_live_call_demo.webm"
            
            # Copy raw webm file
            shutil.copy(video_path, output_webm)
            print(f"Copied webm video to artifact directory: {output_webm}")

            # Convert to mp4 with ffmpeg if available
            ffmpeg_path = shutil.which("ffmpeg")
            if ffmpeg_path:
                print("Converting webm to mp4 via ffmpeg...")
                subprocess.run(["ffmpeg", "-y", "-i", str(video_path), "-c:v", "libx264", "-pix_fmt", "yuv420p", str(output_mp4)], check=True)
                print(f"Converted mp4 saved: {output_mp4}")
            else:
                shutil.copy(video_path, output_mp4)
                print(f"Saved mp4 artifact: {output_mp4}")

if __name__ == "__main__":
    asyncio.run(record_demo())
