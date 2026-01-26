# 2D Animated Training Video Pipeline

> **Goal:** Convert training scripts into professional animated videos with minimal manual intervention.
> **Target Platform:** Mac with Apple Silicon (M1/M2/M3) and 32GB RAM

---

## Table of Contents

1. [Pipeline Overview](#pipeline-overview)
2. [Text-to-Speech (TTS)](#text-to-speech-tts)
3. [Lip Sync](#lip-sync)
4. [2D Character Animation](#2d-character-animation)
5. [Video Composition](#video-composition)
6. [End-to-End Solutions](#end-to-end-solutions)
7. [Recommended Pipeline](#recommended-pipeline)
8. [Installation Guide](#installation-guide)
9. [Workflow Automation](#workflow-automation)
10. [Cost Analysis](#cost-analysis)

---

## Pipeline Overview

```
Training Script (Markdown)
         ↓
    Text-to-Speech (TTS)
         ↓
    Audio File (WAV/MP3)
         ↓
    Lip Sync Generation
         ↓
    Animated Character Video
         ↓
    Video Composition (backgrounds, text, graphics)
         ↓
    Final Training Video (MP4)
```

### Design Goals
- **Efficiency over perfection** - Good enough quality, fast turnaround
- **Local/free tools first** - Minimize API costs and dependencies
- **Automation-friendly** - Scriptable pipeline with CLI tools
- **Mac-compatible** - Works on Apple Silicon with 32GB RAM

---

## Text-to-Speech (TTS)

### Tool Comparison

| Tool | Quality | Speed | Voice Clone | Local | Best For |
|------|---------|-------|-------------|-------|----------|
| **Coqui XTTS v2** | ⭐⭐⭐⭐⭐ | Medium | Yes | Yes | Best overall quality, voice cloning |
| **Bark** | ⭐⭐⭐⭐ | Slow | Limited | Yes | Expressive/emotional, multiple languages |
| **Piper** | ⭐⭐⭐ | ⭐Fast | No | Yes | Fast batch processing, embedded use |
| **Edge TTS** | ⭐⭐⭐⭐ | Fast | No | No* | Free, good quality, easy to use |
| **ElevenLabs** | ⭐⭐⭐⭐⭐ | Fast | Yes | No | Best quality, but paid |

*Edge TTS uses Microsoft's cloud API but is free

### Recommended: Coqui XTTS v2

**Why:** Best balance of quality, voice cloning capability, and local execution.

**Pros:**
- Excellent natural-sounding speech
- Voice cloning from 6-second sample
- 16 languages supported
- Runs locally on Mac (MPS acceleration)
- Apache 2.0 license (commercial use OK)

**Cons:**
- Requires ~8GB VRAM for full quality
- Slower than Piper (~3-5x real-time on Mac)
- Setup can be complex

**Basic Usage:**
```python
from TTS.api import TTS

# Initialize XTTS v2
tts = TTS("tts_models/multilingual/multi-dataset/xtts_v2")

# Generate with voice cloning
tts.tts_to_file(
    text="Welcome to security awareness training.",
    speaker_wav="reference_voice.wav",
    language="en",
    file_path="output.wav"
)
```

### Alternative: Edge TTS (Fastest Setup)

**Why:** Zero setup, free, good quality, fast.

```bash
# Install
pip install edge-tts

# Generate audio
edge-tts --text "Welcome to security training" --write-media output.mp3 --voice en-US-GuyNeural
```

**Available Voices (good for training):**
- `en-US-GuyNeural` - Professional male
- `en-US-JennyNeural` - Professional female
- `en-US-AriaNeural` - Warm female
- `en-GB-RyanNeural` - British male

### Alternative: Piper (Fastest Local)

**Why:** Extremely fast, lightweight, good for batch processing.

```bash
# Install (Mac)
brew install piper-tts

# Generate
echo "Welcome to training" | piper --model en_US-lessac-medium --output_file output.wav
```

---

## Lip Sync

### Tool Comparison

| Tool | Quality | Speed | Mac Support | Ease of Use |
|------|---------|-------|-------------|-------------|
| **SadTalker** | ⭐⭐⭐⭐⭐ | Medium | Good | ⭐⭐⭐⭐ |
| **Wav2Lip** | ⭐⭐⭐⭐ | Fast | Fair | ⭐⭐⭐ |
| **MuseTalk** | ⭐⭐⭐⭐ | Medium | Limited | ⭐⭐ |
| **Easy Wav2Lip** | ⭐⭐⭐⭐ | Fast | Fair | ⭐⭐⭐⭐⭐ |

### Recommended: SadTalker

**Why:** Best quality, full face animation (not just lips), works well on Mac.

**What it does:**
- Takes a single portrait image + audio
- Generates realistic talking head video
- Includes head movement and expressions
- Output: Full animated face video

**Pros:**
- High quality lip sync
- Natural head movements
- Single image input (no video needed)
- GFPGAN enhancer for quality boost
- Apache 2.0 license (commercial OK now!)

**Cons:**
- Requires ~8GB VRAM
- Processing time: ~5 min per 1 min audio
- May have artifacts on complex images

**Setup (Mac):**
```bash
# Clone repository
git clone https://github.com/OpenTalker/SadTalker.git
cd SadTalker

# Create environment
conda create -n sadtalker python=3.8
conda activate sadtalker

# Install dependencies
pip install torch torchvision torchaudio
conda install ffmpeg
pip install -r requirements.txt

# Download models
bash scripts/download_models.sh
```

**Usage:**
```bash
python inference.py \
  --driven_audio audio/training_narration.wav \
  --source_image images/presenter.png \
  --result_dir results/ \
  --still \
  --preprocess full \
  --enhancer gfpgan
```

### Alternative: Wav2Lip

**Why:** Faster processing, better for existing video lip replacement.

```bash
# Basic usage
python inference.py \
  --checkpoint_path checkpoints/wav2lip_gan.pth \
  --face input_video.mp4 \
  --audio narration.wav
```

---

## 2D Character Animation

### Tool Comparison

| Tool | Type | Cost | Learning Curve | Automation |
|------|------|------|----------------|------------|
| **Rive** | Vector animation | Free tier | Medium | Good API |
| **Spine** | Skeletal animation | $69-$299 | High | Limited |
| **Blender (Grease Pencil)** | Full 2D/3D | Free | High | Python API |
| **OpenToonz** | Traditional 2D | Free | High | Limited |
| **Animaker** | Template-based | Freemium | Low | No |
| **CreateStudio** | Template-based | One-time | Low | No |

### Recommended Approach: Static Image + SadTalker

For training videos, **skip complex character animation**. Instead:

1. Create or commission a single presenter illustration (static PNG)
2. Use SadTalker to animate the face based on audio
3. Add scene transitions and graphics in post-production

**Why this works:**
- 90% less effort than rigged animation
- Consistent quality
- Fast to produce
- SadTalker adds natural movements

### Creating Presenter Images

**AI-Generated Options:**
- **Midjourney** - High quality, requires subscription
- **DALL-E 3** - Good quality, pay-per-use
- **Stable Diffusion** (local) - Free, variable quality
- **Leonardo.ai** - Free tier available

**Prompt example:**
```
Professional presenter, corporate training video style, 
front-facing portrait, neutral expression, business attire,
clean background, illustration style, --ar 3:4
```

**Requirements for lip sync:**
- Clear, front-facing face
- Neutral or slight smile expression
- Good lighting
- Resolution: 512x512 minimum

### Alternative: Rive for Interactive/Stylized

If you need stylized, cartoon-style animation:

```javascript
// Rive can be automated via API
const riveInstance = new rive.Rive({
  src: 'presenter.riv',
  canvas: document.getElementById('canvas'),
  autoplay: true,
  stateMachines: 'talking',
});
```

---

## Video Composition

### Tool Comparison

| Tool | Type | Automation | Mac Support | Learning Curve |
|------|------|------------|-------------|----------------|
| **FFmpeg** | CLI | ⭐⭐⭐⭐⭐ | Native | Medium |
| **MoviePy** | Python | ⭐⭐⭐⭐⭐ | Yes | Low |
| **DaVinci Resolve** | NLE | Limited | Yes | Medium |
| **Shotcut** | NLE | None | Yes | Low |

### Recommended: FFmpeg + MoviePy

**Why:** Fully scriptable, free, powerful.

### FFmpeg Common Operations

```bash
# Overlay presenter on background
ffmpeg -i background.mp4 -i presenter.mp4 \
  -filter_complex "[1:v]scale=400:-1[presenter];[0:v][presenter]overlay=50:H-h-50" \
  output.mp4

# Add text overlay
ffmpeg -i input.mp4 \
  -vf "drawtext=text='Phishing Awareness':fontsize=48:fontcolor=white:x=(w-text_w)/2:y=50" \
  output.mp4

# Concatenate videos
ffmpeg -f concat -i filelist.txt -c copy output.mp4

# Add background music (ducked)
ffmpeg -i video.mp4 -i music.mp3 \
  -filter_complex "[1:a]volume=0.2[music];[0:a][music]amix=inputs=2" \
  output.mp4
```

### MoviePy Pipeline Example

```python
from moviepy.editor import *
import os

def create_training_video(
    presenter_video: str,
    background_image: str,
    title: str,
    output_path: str
):
    # Load components
    presenter = VideoFileClip(presenter_video)
    bg = ImageClip(background_image).set_duration(presenter.duration)
    
    # Position presenter (bottom right)
    presenter = presenter.resize(height=400)
    presenter = presenter.set_position(('right', 'bottom'))
    
    # Create title
    title_clip = TextClip(
        title,
        fontsize=60,
        color='white',
        font='Arial-Bold'
    ).set_position(('center', 50)).set_duration(5)
    
    # Composite
    final = CompositeVideoClip([bg, presenter, title_clip])
    
    # Export
    final.write_videofile(
        output_path,
        fps=24,
        codec='libx264',
        audio_codec='aac'
    )

# Usage
create_training_video(
    presenter_video="sadtalker_output.mp4",
    background_image="backgrounds/corporate_blue.png",
    title="Phishing Awareness Training",
    output_path="final_training.mp4"
)
```

---

## End-to-End Solutions

### Commercial Reference (for comparison)

| Service | Cost | Quality | Effort |
|---------|------|---------|--------|
| **D-ID** | $5.99/min | Excellent | Minutes |
| **HeyGen** | $24-$89/mo | Excellent | Minutes |
| **Synthesia** | $22-$67/mo | Excellent | Minutes |
| **Colossyan** | Custom | Excellent | Minutes |

### Open Source / Self-Hosted Alternatives

#### SadTalker (Best Value)
- Cost: Free
- Quality: Very good
- Effort: Medium (setup required)
- Best for: Talking head videos from single images

#### Wav2Lip + D-ID Clone Projects
Various community projects attempt to replicate D-ID functionality:
- Quality varies significantly
- May require significant GPU resources
- Often research-focused, not production-ready

### Recommended Approach

**For cybersecurity training videos, use:**

1. **SadTalker** for presenter animation (free, local)
2. **Coqui XTTS or Edge TTS** for narration
3. **MoviePy/FFmpeg** for composition
4. **Canva** or **Figma** for backgrounds and graphics (free tiers)

This provides 80% of commercial quality at nearly zero cost.

---

## Recommended Pipeline

### Complete Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRAINING VIDEO PIPELINE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. SCRIPT PREPARATION                                          │
│     └── training-script.md → cleaned text for TTS               │
│                                                                  │
│  2. TEXT-TO-SPEECH                                              │
│     └── Edge TTS or Coqui XTTS → narration.wav                  │
│                                                                  │
│  3. LIP SYNC GENERATION                                         │
│     └── SadTalker (presenter.png + narration.wav) → talking.mp4 │
│                                                                  │
│  4. ASSET PREPARATION                                           │
│     └── Backgrounds, graphics, lower thirds in Canva/Figma      │
│                                                                  │
│  5. VIDEO COMPOSITION                                           │
│     └── MoviePy/FFmpeg → final_training.mp4                     │
│                                                                  │
│  6. QUALITY CHECK & EXPORT                                      │
│     └── Review, adjust timing, export final                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Processing Time Estimates

For a 5-minute training video:
- Script cleanup: 5 minutes
- TTS generation: 2-5 minutes
- Lip sync (SadTalker): 15-25 minutes
- Composition: 5-10 minutes
- **Total: 30-45 minutes** (mostly automated)

---

## Installation Guide

### Prerequisites (Mac)

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and tools
brew install python@3.10 ffmpeg

# Install Conda (for SadTalker)
brew install --cask miniconda

# Initialize conda
conda init zsh  # or bash
```

### TTS Setup (Edge TTS - Easiest)

```bash
pip install edge-tts
```

### TTS Setup (Coqui XTTS - Best Quality)

```bash
pip install TTS
```

### SadTalker Setup

```bash
# Clone and setup
git clone https://github.com/OpenTalker/SadTalker.git
cd SadTalker

# Create environment
conda create -n sadtalker python=3.8
conda activate sadtalker

# Install PyTorch for Mac
pip install torch torchvision torchaudio

# Install other dependencies
conda install ffmpeg
pip install -r requirements.txt

# Download models
bash scripts/download_models.sh
```

### MoviePy Setup

```bash
pip install moviepy
```

### Verify Installation

```bash
# Test Edge TTS
edge-tts --text "Hello world" --write-media test.mp3

# Test FFmpeg
ffmpeg -version

# Test MoviePy
python -c "from moviepy.editor import *; print('MoviePy OK')"

# Test SadTalker
cd SadTalker
python inference.py --help
```

---

## Workflow Automation

### Complete Pipeline Script

```python
#!/usr/bin/env python3
"""
Training Video Generator
Converts markdown scripts into animated training videos.
"""

import os
import re
import subprocess
from pathlib import Path
from moviepy.editor import *

class TrainingVideoGenerator:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def extract_narration(self, script_path: str) -> str:
        """Extract narration text from markdown script."""
        with open(script_path) as f:
            content = f.read()
        
        # Extract content between [NARRATOR] tags
        pattern = r'\*\*\[NARRATOR\]\*\*\n\n(.*?)(?=\n\n\*\*\[|---|\Z)'
        matches = re.findall(pattern, content, re.DOTALL)
        
        narration = ' '.join(matches)
        # Clean up markdown formatting
        narration = re.sub(r'\*\*.*?\*\*', '', narration)
        narration = re.sub(r'\[.*?\]', '', narration)
        narration = narration.replace('\n', ' ').strip()
        
        return narration
    
    def generate_tts(self, text: str, output_path: str, voice: str = "en-US-GuyNeural"):
        """Generate audio using Edge TTS."""
        cmd = [
            "edge-tts",
            "--text", text,
            "--write-media", output_path,
            "--voice", voice
        ]
        subprocess.run(cmd, check=True)
        print(f"Generated audio: {output_path}")
        
    def generate_lipsync(self, audio_path: str, image_path: str, output_path: str):
        """Generate lip-synced video using SadTalker."""
        sadtalker_dir = os.environ.get("SADTALKER_DIR", "~/SadTalker")
        
        cmd = [
            "python", "inference.py",
            "--driven_audio", audio_path,
            "--source_image", image_path,
            "--result_dir", str(self.output_dir),
            "--still",
            "--preprocess", "full",
            "--enhancer", "gfpgan"
        ]
        
        subprocess.run(cmd, cwd=sadtalker_dir, check=True)
        print(f"Generated lip-sync video: {output_path}")
        
    def compose_final_video(
        self,
        presenter_video: str,
        background: str,
        title: str,
        output_path: str
    ):
        """Compose final training video."""
        # Load clips
        presenter = VideoFileClip(presenter_video)
        
        if background.endswith(('.mp4', '.mov')):
            bg = VideoFileClip(background).loop(duration=presenter.duration)
        else:
            bg = ImageClip(background).set_duration(presenter.duration)
        
        # Resize and position presenter
        presenter = presenter.resize(height=int(bg.h * 0.6))
        presenter = presenter.set_position(('right', 'bottom'))
        
        # Create title
        title_clip = (TextClip(title, fontsize=50, color='white', font='Arial-Bold')
                      .set_position(('center', 30))
                      .set_duration(4)
                      .fadeout(1))
        
        # Composite
        final = CompositeVideoClip([bg, presenter, title_clip])
        final = final.set_audio(presenter.audio)
        
        # Export
        final.write_videofile(
            output_path,
            fps=24,
            codec='libx264',
            audio_codec='aac',
            threads=4
        )
        print(f"Final video: {output_path}")
        
    def process_script(
        self,
        script_path: str,
        presenter_image: str,
        background: str,
        title: str
    ) -> str:
        """Complete pipeline: script → final video."""
        base_name = Path(script_path).stem
        
        # Step 1: Extract narration
        print("Extracting narration...")
        narration = self.extract_narration(script_path)
        
        # Step 2: Generate TTS
        audio_path = self.output_dir / f"{base_name}_audio.mp3"
        print("Generating audio...")
        self.generate_tts(narration, str(audio_path))
        
        # Step 3: Generate lip sync
        lipsync_path = self.output_dir / f"{base_name}_lipsync.mp4"
        print("Generating lip sync...")
        self.generate_lipsync(str(audio_path), presenter_image, str(lipsync_path))
        
        # Step 4: Compose final video
        output_path = self.output_dir / f"{base_name}_final.mp4"
        print("Composing final video...")
        self.compose_final_video(str(lipsync_path), background, title, str(output_path))
        
        return str(output_path)


# Example usage
if __name__ == "__main__":
    generator = TrainingVideoGenerator("./videos")
    
    result = generator.process_script(
        script_path="Training-Awareness/Phishing/training-script.md",
        presenter_image="assets/presenter.png",
        background="assets/backgrounds/corporate_blue.png",
        title="Phishing Awareness Training"
    )
    
    print(f"Complete! Video saved to: {result}")
```

### Batch Processing

```bash
#!/bin/bash
# batch_generate.sh - Generate all training videos

TOPICS=(
    "Phishing"
    "Password-Security"
    "Social-Engineering"
    "Ransomware"
    "Data-Protection"
    "Physical-Security"
    "Incident-Response"
    "Compliance"
    "Remote-Work"
    "Mobile-Security"
)

for topic in "${TOPICS[@]}"; do
    echo "Processing: $topic"
    python generate_video.py \
        --script "Training-Awareness/$topic/training-script.md" \
        --presenter "assets/presenter.png" \
        --background "assets/bg_${topic,,}.png" \
        --output "videos/${topic}.mp4"
done

echo "All videos generated!"
```

---

## Cost Analysis

### Free/Local Pipeline

| Component | Tool | Cost |
|-----------|------|------|
| TTS | Edge TTS or Coqui | $0 |
| Lip Sync | SadTalker | $0 |
| Composition | FFmpeg + MoviePy | $0 |
| Graphics | Canva Free | $0 |
| Presenter Image | Stable Diffusion local | $0 |
| **Total** | | **$0** |

### Budget Quality Boost

| Component | Tool | Cost |
|-----------|------|------|
| TTS | ElevenLabs starter | $5/month |
| Lip Sync | SadTalker | $0 |
| Composition | FFmpeg + MoviePy | $0 |
| Graphics | Canva Pro | $13/month |
| Presenter Image | Midjourney | $10/month |
| **Total** | | **~$28/month** |

### Commercial Comparison

| Approach | Cost per 5-min video | Annual (20 videos) |
|----------|---------------------|-------------------|
| **Local Pipeline (Free)** | $0 | $0 |
| **Local + Paid TTS** | ~$2 | ~$40 |
| **D-ID** | ~$30 | ~$600 |
| **Synthesia** | ~$50 | ~$1,000 |
| **Professional Production** | ~$2,000+ | ~$40,000+ |

---

## Quality vs Efficiency Recommendations

### Highest Quality (More Time)
- Coqui XTTS with custom voice clone
- SadTalker with GFPGAN enhancer
- Custom illustrated presenter
- Professional background design

### Best Balance (Recommended)
- Edge TTS with professional voices
- SadTalker standard mode
- AI-generated or stock presenter image
- Template backgrounds from Canva

### Fastest Production
- Edge TTS (no setup)
- SadTalker quick mode (no enhancer)
- Stock presenter image
- Solid color backgrounds

---

## Troubleshooting

### SadTalker Issues

**"CUDA out of memory"**
```bash
# Use CPU mode or reduce resolution
python inference.py ... --preprocess resize
```

**"Audio sync issues"**
- Ensure audio is mono, 16kHz or 22kHz
- Convert audio: `ffmpeg -i input.mp3 -ar 16000 -ac 1 output.wav`

### TTS Issues

**Edge TTS rate limiting**
- Add delays between requests
- Split long scripts into chunks

**Coqui voice quality issues**
- Use longer reference audio (10-15 seconds)
- Ensure clean reference recording

### FFmpeg Issues

**"Codec not found"**
```bash
brew reinstall ffmpeg
```

---

## Resources

### Tutorials
- [SadTalker Documentation](https://github.com/OpenTalker/SadTalker)
- [Coqui TTS Documentation](https://tts.readthedocs.io/)
- [MoviePy Documentation](https://zulko.github.io/moviepy/)

### Asset Sources
- [Unsplash](https://unsplash.com) - Free backgrounds
- [Pexels](https://pexels.com) - Free stock photos
- [Canva](https://canva.com) - Free design templates
- [Mixkit](https://mixkit.co) - Free music and sound effects

### Communities
- [r/LocalLLaMA](https://reddit.com/r/LocalLLaMA) - Local AI discussion
- [Hugging Face](https://huggingface.co) - Model hosting
- [SadTalker Discord](https://discord.gg/rrayYqZ4tf) - Support

---

## Summary

The recommended pipeline for security training videos:

1. **TTS:** Edge TTS (fastest) or Coqui XTTS (best quality)
2. **Lip Sync:** SadTalker (best quality/automation balance)
3. **Animation:** Static image + SadTalker face animation
4. **Composition:** MoviePy for scripted assembly, FFmpeg for processing
5. **Cost:** $0 for local pipeline, $28/month for enhanced quality

This approach produces professional-looking training videos at a fraction of commercial costs while maintaining full automation capability.

---

*Last updated: January 2025*
