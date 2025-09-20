# New Sorting

```py
delta_blocks = abs(bb_count_old - bb_count_new)
block_ratio = min(bb_count_old, bb_count_new) / max(bb_count_old, bb_count_new)  # [0,1]
similarity = ratio

# Weight logic
if delta_blocks == 0:
    # Structural stability -> downweight textual diffs
    change_score = (1 - similarity) * 0.2
else:
    # Structural change -> emphasize block differences
    change_score = (1 - similarity) * 0.6 + (1 - block_ratio) * 0.4
```