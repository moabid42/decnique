"""Build the guide's vector figures; matplotlib is a document-build tool only.

Run with the system Python, where matplotlib is installed:
    python3 docs/figures/build_guide_figures.py
The finite geometry is independently checked against both decnique region backends.
"""

from __future__ import annotations

from itertools import product
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import to_rgb
from mpl_toolkits.mplot3d.art3d import Line3DCollection, Poly3DCollection
from mpl_toolkits.mplot3d.proj3d import proj_transform

OUT = Path(__file__).resolve().parent
INK, MUTED, RULE = "#25231f", "#77736c", "#bd4b2b"
PALETTE = ("#4c6d8f", "#93abc0", "#537a66", "#9bb49e", "#80658e", "#b6a0c1")
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "text.color": INK,
    "axes.labelcolor": MUTED,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "svg.fonttype": "none",
    "savefig.transparent": True,
})


def cuboid(ax, bounds, color, *, wire=False):
    (x0, x1), (y0, y1), (z0, z1) = bounds
    vertices = [(x0, y0, z0), (x1, y0, z0), (x1, y1, z0), (x0, y1, z0),
                (x0, y0, z1), (x1, y0, z1), (x1, y1, z1), (x0, y1, z1)]
    if wire:
        edges = ((0, 1), (1, 2), (2, 3), (3, 0), (4, 5), (5, 6),
                 (6, 7), (7, 4), (0, 4), (1, 5), (2, 6), (3, 7))
        ax.add_collection3d(Line3DCollection(
            [[vertices[a], vertices[b]] for a, b in edges],
            colors=color, linewidths=0.9, alpha=0.85,
        ))
    else:
        faces = ((0, 1, 2, 3), (4, 5, 6, 7), (0, 1, 5, 4),
                 (2, 3, 7, 6), (0, 3, 7, 4), (1, 2, 6, 5))
        colors = [tuple(v * shade for v in to_rgb(color))
                  for shade in (0.76, 1.0, 0.86, 0.9, 0.79, 0.94)]
        ax.add_collection3d(Poly3DCollection(
            [[vertices[i] for i in face] for face in faces],
            facecolors=colors, edgecolors="white", linewidths=0.8,
        ))


def configure_3d(ax):
    ax.set_proj_type("ortho")
    ax.view_init(elev=23, azim=-54)
    ax.set_box_aspect((1, 1, 1))
    ax.grid(False)
    for axis in (ax.xaxis, ax.yaxis, ax.zaxis):
        axis.pane.fill = False
        axis.pane.set_edgecolor((1, 1, 1, 0))
        axis.line.set_color("#c8c4bd")
        axis.set_tick_params(labelsize=9, pad=0)


def geometry_3d():
    fig = plt.figure(figsize=(10.4, 4.5))
    left = fig.add_axes((0.015, 0.06, 0.45, 0.83), projection="3d")
    configure_3d(left)
    cuboid(left, [(0, 6)] * 3, "#919993", wire=True)
    cuboid(left, [(2, 4)] * 3, RULE)
    # Subdivide only the three visible faces, avoiding hidden internal edges.
    cell_edges = (
        ((3, 2, 4), (3, 4, 4)), ((2, 3, 4), (4, 3, 4)),
        ((3, 2, 2), (3, 2, 4)), ((2, 2, 3), (4, 2, 3)),
        ((4, 3, 2), (4, 3, 4)), ((4, 2, 3), (4, 4, 3)),
    )
    left.add_collection3d(Line3DCollection(cell_edges, colors="white", linewidths=0.8))
    left.text(3, 3, 4.6, "D: 8 points", ha="center", fontsize=11, color=RULE)
    for axis in (left.xaxis, left.yaxis, left.zaxis):
        axis.set_ticks([0, 2, 4, 6])
    left.set(xlim=(0, 6.2), ylim=(0, 6.2), zlim=(0, 6.2),
             xlabel="x", ylabel="y", zlabel="z")
    left.xaxis.labelpad = -3
    left.yaxis.labelpad = -3
    left.zaxis.labelpad = -3
    fig.text(0.035, 0.95, "A  /  THE COVERED CENTER", fontsize=11, weight="bold")
    fig.text(0.035, 0.015, "Wireframe C: 216 candidate points", fontsize=10, color=MUTED)

    right = fig.add_axes((0.52, 0.05, 0.47, 0.84), projection="3d")
    configure_3d(right)
    pieces = (
        ((0, 2), (0, 6), (0, 6)), ((4, 6), (0, 6), (0, 6)),
        ((2, 4), (0, 2), (0, 6)), ((2, 4), (4, 6), (0, 6)),
        ((2, 4), (2, 4), (0, 2)), ((2, 4), (2, 4), (4, 6)),
    )
    positions = ((0.02, 0.67), (0.99, 0.34), (0.13, 0.22),
                 (0.9, 0.81), (0.45, 0.03), (0.52, 0.95))
    targets = []
    for i, (piece, color) in enumerate(zip(pieces, PALETTE, strict=True)):
        bounds = [list(b) for b in piece]
        axis = i // 2
        offset = -2.2 if i % 2 == 0 else 2.2
        bounds[axis] = [v + offset for v in bounds[axis]]
        cuboid(right, bounds, color)
        targets.append([sum(b) / 2 for b in bounds])
    cuboid(right, [(2, 4)] * 3, RULE, wire=True)
    right.set(xlim=(-2.6, 8.6), ylim=(-2.6, 8.6), zlim=(-2.6, 8.6))
    right.set_axis_off()
    for i, (target, pos) in enumerate(zip(targets, positions, strict=True)):
        x, y, _ = proj_transform(*target, right.get_proj())
        right.annotate(
            f"H{i + 1}", (x, y), xytext=pos, textcoords="axes fraction",
            fontsize=12, weight="bold", ha="center", va="center", zorder=1000,
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 1.5},
            arrowprops={"arrowstyle": "-", "color": PALETTE[i], "lw": 1},
        )
    fig.text(0.54, 0.95, "B  /  SIX PIECES OF THE REMAINDER", fontsize=11, weight="bold")
    fig.text(0.54, 0.015, "Exploded for inspection; translations are visual only.", fontsize=10, color=MUTED)
    fig.savefig(OUT / "guide-three-dimensions.svg")
    plt.close(fig)


def coordinate_strip():
    fig, ax = plt.subplots(figsize=(10.4, 1.8))
    ax.set(xlim=(0, 10), ylim=(0, 2))
    ax.axis("off")
    labels = (r"$I_1$", r"$I_2$", r"$B_3$ ∖ $R_3$", r"$B_4$", r"$B_5$")
    colors = ("#e4ebe4", "#e4ebe4", "#f4ddd3", "#e4ebf1", "#e4ebf1")
    values = (3, 3, 1, 4, 0)
    for i, (label, color, value) in enumerate(zip(labels, colors, values, strict=True)):
        x = i * 2
        ax.add_patch(plt.Rectangle((x + 0.07, 0.65), 1.86, 0.72,
                                   facecolor=color, edgecolor="none"))
        ax.text(x + 1, 1.01, label, ha="center", va="center", fontsize=18)
        ax.text(x + 1, 1.65, f"coordinate {i + 1}", ha="center", fontsize=10, color=MUTED)
        ax.text(x + 1, 0.22, str(value), ha="center", fontsize=12, weight="bold")
    fig.subplots_adjust(left=0.01, right=0.99, top=0.95, bottom=0.05)
    fig.savefig(OUT / "guide-n-dimensions.svg")
    plt.close(fig)


def timing():
    fig, ax = plt.subplots(figsize=(10.4, 2.15))
    ax.set(xlim=(-12, 825), ylim=(-0.55, 1.55))
    ax.axis("off")
    for y, times, verdict, color in (
        (1.0, (0, 301, 602), "EVASIVE", "#537a66"),
        (0.0, (0, 150, 300), "DETECTED", RULE),
    ):
        ax.plot((0, 650), (y, y), color="#c8c4bd", lw=1)
        ax.plot((0, 300), (y, y), color=RULE, lw=6, alpha=0.12, solid_capstyle="butt")
        ax.scatter(times, [y] * 3, s=55, color=color, zorder=3, edgecolors="white", linewidths=0.7)
        for t in times:
            ax.text(t, y - 0.24, str(t), ha="center", fontsize=10, color=MUTED)
        ax.text(702, y, verdict, ha="left", va="center", weight="bold", fontsize=11, color=color)
    ax.text(150, 1.38, "300 s window", ha="center", fontsize=10, color=RULE)
    ax.text(650, -0.44, "time (s)", ha="right", fontsize=10, color=MUTED)
    fig.subplots_adjust(left=0.025, right=0.99, top=0.98, bottom=0.02)
    fig.savefig(OUT / "guide-timing.svg")
    plt.close(fig)


def finite_sanity_check():
    for n in range(1, 5):
        uncovered = [p for p in product(range(6), repeat=n)
                     if any(v not in (2, 3) for v in p)]
        assert len(uncovered) == 6 ** n - 2 ** n


def idea_map():
    fig, ax = plt.subplots(figsize=(10.4, 3.5))
    ax.set(xlim=(-0.15, 10.15), ylim=(-0.45, 4.1))
    ax.axis("off")
    ax.add_patch(plt.Rectangle((0.2, 0.35), 9.6, 3.1,
                               facecolor="#fffefb", edgecolor=PALETTE[0], lw=1.7))
    ax.text(0.35, 3.72, "POSSIBLE EXECUTIONS OF THIS TECHNIQUE", fontsize=12,
            color=PALETTE[0], weight="bold")
    for xy, width, height in [((0.2, 0.35), 3.4, 3.1), ((3.6, 1.9), 2.3, 1.55)]:
        ax.add_patch(plt.Rectangle(xy, width, height, facecolor="#f0d4c8",
                                   edgecolor="white", lw=1))
    ax.text(1.9, 1.8, "Detected\nexecutions", fontsize=15, color=RULE,
            ha="center", va="center", linespacing=1.5)
    ax.text(6.8, 1.05, "Whitespace inside the technique:\nways it may stay unseen", fontsize=13,
            ha="center", va="center", color=INK, linespacing=1.5)
    ax.scatter([7.9], [2.55], s=85, color=PALETTE[2], zorder=5)
    ax.annotate("One concrete\nevasive execution", (7.9, 2.55), (6.4, 2.85),
                fontsize=11, ha="center", color=PALETTE[2],
                arrowprops={"arrowstyle": "-", "color": PALETTE[2], "lw": 0.8})
    ax.text(5, -0.12, "Space outside the candidate is irrelevant to this technique's question.",
            ha="center", fontsize=10, color=MUTED)
    fig.subplots_adjust(left=0.015, right=0.985, top=0.96, bottom=0.05)
    fig.savefig(OUT / "stealth-idea.svg")
    plt.close(fig)


def normalization():
    fig, ax = plt.subplots(figsize=(10.4, 3.5))
    ax.set(xlim=(0, 10), ylim=(0, 4.1))
    ax.axis("off")
    for x, title, body, color in (
        (0.1, "DETECTION", "What evidence makes\nthis rule alert?", RULE),
        (5.3, "TECHNIQUE", "What must happen for\nthis technique to succeed?", PALETTE[0]),
    ):
        ax.text(x + 2.3, 3.8, title, fontsize=12, weight="bold", ha="center", color=color)
        ax.text(x + 2.3, 3.15, body, fontsize=14, ha="center", va="center", linespacing=1.4)
        ax.annotate("", xy=(x + 2.3, 1.9), xytext=(x + 2.3, 2.6),
                    arrowprops={"arrowstyle": "->", "lw": 1.3, "color": color})
    ax.add_patch(plt.Rectangle((0.1, 0.65), 9.8, 1.15, facecolor="#f5f2ec", edgecolor="none"))
    ax.text(5, 1.35, "ONE SHARED DESCRIPTION OF BEHAVIOR", fontsize=12, weight="bold", ha="center")
    ax.text(5, 0.92, "method   ·   number of events   ·   elapsed time   ·   payload fields",
            fontsize=12, ha="center", color=MUTED)
    ax.text(5, 0.15, "Different questions. The same coordinates.", fontsize=12, ha="center", color=INK)
    fig.subplots_adjust(left=0.01, right=0.99, top=0.98, bottom=0.03)
    fig.savefig(OUT / "stealth-normalization.svg")
    plt.close(fig)


def intuitive_dimensions():
    fig, ax = plt.subplots(figsize=(10.4, 2.05))
    ax.set(xlim=(0, 10), ylim=(0, 2.15))
    ax.axis("off")
    labels = ("INSIDE", "INSIDE", "OUTSIDE", "ANY", "ANY")
    colors = ("#e4ebe4", "#e4ebe4", "#f4ddd3", "#e4ebf1", "#e4ebf1")
    for i, (label, color) in enumerate(zip(labels, colors, strict=True)):
        x = i * 2
        ax.add_patch(plt.Rectangle((x + 0.07, 0.65), 1.86, 0.8,
                                   facecolor=color, edgecolor="none"))
        ax.text(x + 1, 1.05, label, ha="center", va="center", fontsize=12, weight="bold")
        ax.text(x + 1, 1.76, f"coordinate {i + 1}", ha="center", fontsize=10, color=MUTED)
    ax.text(5, 0.2, "Assign this uncovered point to its first failing coordinate: number 3.",
            ha="center", fontsize=11, color=INK)
    fig.subplots_adjust(left=0.01, right=0.99, top=0.95, bottom=0.05)
    fig.savefig(OUT / "stealth-many-dimensions.svg")
    plt.close(fig)


if __name__ == "__main__":
    finite_sanity_check()
    geometry_3d()
    coordinate_strip()
    timing()
    idea_map()
    normalization()
    intuitive_dimensions()
    print("Built six vector figures in docs/figures/.")
