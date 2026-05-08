# docs/architecture.py — emoji-free version for Windows matplotlib
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

BG_DARK    = "#0a0f1e"
BG_CARD    = "#111827"
ACCENT     = "#00d4ff"
PURPLE     = "#7b2ff7"
GREEN      = "#00c853"
ORANGE     = "#ff6b35"
YELLOW     = "#f39c12"
RED        = "#ff2d55"
TEXT_LIGHT = "#e8eaf6"
TEXT_DIM   = "#8892b0"
BORDER     = "#1e2d40"


def draw_box(ax, x, y, w, h, border_color, text, fontsize=9):
    box = FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle  = "round,pad=0.02",
        facecolor = BG_CARD,
        edgecolor = border_color,
        linewidth = 2,
        zorder    = 3,
    )
    ax.add_patch(box)
    ax.text(
        x, y, text,
        ha             = "center",
        va             = "center",
        fontsize       = fontsize,
        color          = TEXT_LIGHT,
        fontfamily     = "monospace",
        zorder         = 4,
        multialignment = "center",
    )


def draw_arrow(ax, x0, y0, x1, y1):
    ax.annotate(
        "",
        xy       = (x1, y1),
        xytext   = (x0, y0),
        arrowprops = dict(
            arrowstyle = "->",
            color      = BORDER,
            lw         = 1.5,
        ),
        zorder = 2,
    )


def generate_architecture_png(
    output_path: str = "docs/architecture.png"
) -> str:
    fig, ax = plt.subplots(figsize=(14, 8))
    fig.patch.set_facecolor(BG_DARK)
    ax.set_facecolor(BG_DARK)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8)
    ax.axis("off")

    # Title
    ax.text(
        7, 7.65,
        "Campus Fraud Shield  —  4-Engine Detection Pipeline",
        ha="center", va="center",
        fontsize=13, fontweight="bold",
        color=ACCENT, fontfamily="monospace",
    )

    # Input box
    draw_box(ax, 7, 6.85, 4.0, 0.55, ACCENT,
             "[INPUT]  WhatsApp / SMS Message", fontsize=10)

    # Arrows: input → engines
    for ex in [1.2, 4.2, 9.8, 12.8]:
        draw_arrow(ax, 7, 6.57, ex, 5.65)

    # Engine boxes
    engines = [
        (1.2,  5.2, PURPLE, "[1] Rules Engine\n50+ regex patterns\nWeight: 35%"),
        (4.2,  5.2, GREEN,  "[2] Domain Check\nURL / email verify\nWeight: 30%"),
        (9.8,  5.2, ACCENT, "[3] Semantic AI\nall-MiniLM-L6-v2\nWeight: 20%"),
        (12.8, 5.2, ORANGE, "[4] FAISS History\nCommunity reports\nWeight: 15%"),
    ]
    for ex, ey, color, label in engines:
        draw_box(ax, ex, ey, 2.3, 1.0, color, label, fontsize=8)

    # Arrows: engines → scorer
    for ex in [1.2, 4.2, 9.8, 12.8]:
        draw_arrow(ax, ex, 4.70, 7, 3.90)

    # Scorer box
    draw_box(
        ax, 7, 3.45, 6.0, 0.80, YELLOW,
        "[SCORER]  Weighted Formula\n"
        "Final = 0.35xRules + 0.30xDomain + 0.20xML + 0.15xHistory",
        fontsize=9,
    )

    # Override note
    ax.text(
        7, 2.95,
        "Override: OTP sharing -> force SCAM  |  High rules score -> push SCAM range",
        ha="center", va="center",
        fontsize=7.5, color=TEXT_DIM,
        fontfamily="monospace", style="italic",
    )

    # Arrows: scorer → verdicts
    for vx in [2.5, 7.0, 11.5]:
        draw_arrow(ax, 7, 3.05, vx, 2.15)

    # Verdict boxes
    verdicts = [
        (2.5,  1.7, RED,    "[SCAM]\nscore >= 70"),
        (7.0,  1.7, YELLOW, "[SUSPICIOUS]\n40 <= score < 70"),
        (11.5, 1.7, GREEN,  "[SAFE]\nscore < 40"),
    ]
    for vx, vy, color, label in verdicts:
        draw_box(ax, vx, vy, 2.8, 0.75, color, label, fontsize=9)

    # Output features
    features = [
        (2.5,  0.90, "Confidence Score\nAction Steps\nComplaint Text"),
        (7.0,  0.90, "Conflict Warning\nManual Verify\nAction Steps"),
        (11.5, 0.90, "Safe Confirmation\nVerify Tip"),
    ]
    for fx, fy, label in features:
        ax.text(
            fx, fy, label,
            ha="center", va="center",
            fontsize=7, color=TEXT_DIM,
            fontfamily="monospace",
            multialignment="center",
        )

    # Legend
    legend_items = [
        mpatches.Patch(color=PURPLE, label="Rules Engine  35%"),
        mpatches.Patch(color=GREEN,  label="Domain Check  30%"),
        mpatches.Patch(color=ACCENT, label="Semantic AI   20%"),
        mpatches.Patch(color=ORANGE, label="FAISS History 15%"),
    ]
    ax.legend(
        handles    = legend_items,
        loc        = "lower right",
        fontsize   = 8,
        facecolor  = BG_CARD,
        edgecolor  = BORDER,
        labelcolor = TEXT_LIGHT,
        framealpha = 0.9,
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.tight_layout(pad=0.5)
    plt.savefig(
        output_path,
        dpi         = 150,
        bbox_inches = "tight",
        facecolor   = BG_DARK,
    )
    plt.close()
    print(f"Architecture saved: {os.path.abspath(output_path)}")
    return os.path.abspath(output_path)


if __name__ == "__main__":
    generate_architecture_png()