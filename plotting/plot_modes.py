import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Define the paths and parameters
results_dir = "../results"
results_dir2 = "../results_old/third"
plot_dir = "plots"
if not os.path.exists(plot_dir):
    os.makedirs(plot_dir)
other_modes_only_use_even_split = True  # Set to True if you want to use only the 'even' split for other modes

# Update the modes and case order to include prins_tcp and omit splits for prins
modes = [
    "base",
    "e2e",
    "h2h",
    "prins",
    "prins_tcp",
]

msg_sizes = ["small", "middle", "large"]
splits = ["ciphertext", "even", "aad"]
lower_percentile = 1
upper_percentile = 99

# Adjust figure settings for double-column format
single_column_width = 3.5  # inches
double_column_width = 7.0  # inches
font_size = 15  # Adjust font size for readability in papers
# Adjust figure settings
plt.rcParams.update({'font.size': font_size})

plt.rc('text', usetex=True)
plt.rc('font', family='serif')

def read_data_file(filepath):
    """Read time durations from a data file."""
    try:
        with open(filepath, 'r') as f:
            data = [float(line.strip()) for line in f if line.strip()]
        return data
    except FileNotFoundError:
        print(f"Warning: File {filepath} not found")
        return []

def filter_outliers(data, lower_percentile, upper_percentile):
    """Filter out data outside the specified percentile range."""
    if not data:
        return []
    lower = np.percentile(data, lower_percentile)
    upper = np.percentile(data, upper_percentile)
    return [x for x in data if lower <= x <= upper]

# Collect data for the specified modes
all_data = []
for mode in modes:
    for msg_size in msg_sizes:
        for split in splits:
            for start_type in ["warm", "cold"]:
                if other_modes_only_use_even_split and mode in ["base","e2e","h2h"]:
                    if split != "even":
                        continue
                filename = f"{mode}_{msg_size}_{split}_{start_type}.txt"
                filepath = os.path.join(results_dir, filename)
                data = read_data_file(filepath)
                data = filter_outliers(data, lower_percentile, upper_percentile)
                if data:
                    label = f"{mode}"
                    all_data.extend([(label, start_type, value) for value in data])

# Create the bar plot
if all_data:
    df = pd.DataFrame(all_data, columns=['Case', 'Start Type', 'Duration'])
    bar_data = df.groupby(['Case', 'Start Type'])['Duration'].agg(['mean', 'std']).reset_index()
    bar_data['Case'] = pd.Categorical(bar_data['Case'], categories=modes, ordered=True)
    bar_data = bar_data.sort_values('Case')

    # Calculate and print the means for each mode and start type
    for mode in modes:
        for start_type in ["cold", "warm"]:
            subset = bar_data[(bar_data['Case'] == mode) & (bar_data['Start Type'] == start_type)]
            if not subset.empty:
                mean = subset['mean'].values[0]
                print(f"Mean for {mode} ({start_type}): {mean:.2f} ms")

    # Create the bar plot without Seaborn
    fig, ax = plt.subplots(figsize=(double_column_width, 3.5))

    # Define parameters
    modes = bar_data['Case'].unique()
    start_types = bar_data['Start Type'].unique()
    x = np.arange(len(modes))  # Positions for the groups (modes)
    width = 0.35  # Width of each bar
    colors = ['#1f77b4', '#ff7f0e']  # Define colors for "cold" and "warm"

    # Plot bars for each Start Type
    for j, start_type in enumerate(start_types):
        offset = (j - len(start_types) / 2) * width  # Offset bars within each group
        for i, case in enumerate(modes):
            subset = bar_data[(bar_data['Case'] == case) & (bar_data['Start Type'] == start_type)]
            if not subset.empty:
                mean = subset['mean'].values[0]
                std = subset['std'].values[0]
                ax.bar(
                    x[i] + offset, mean, width, label=start_type if i == 0 else None,  # Add legend only once
                    edgecolor='black', linewidth=0.1,
                    yerr=std, capsize=5, color=colors[j]
                )

    # Customize the plot
    ax.set_ylabel("Mean Latency [ms]", fontsize=font_size, labelpad=1)
    ax.set_xlabel("Mode", fontsize=font_size, labelpad=1)
    ax.set_xticks(x - width / 2)  # Center the x-ticks
    ax.set_xticklabels(modes, fontsize=font_size)
    ax.tick_params(axis='x', pad=2)
    ax.tick_params(axis='y', pad=1)
    # ax.grid(axis='y', linestyle='--', alpha=0.7)  # Add horizontal grid lines
    ax.grid(axis='y', alpha=0.7)  # Add horizontal grid lines
    ax.legend(title="Start Type", fontsize=font_size, title_fontsize=font_size)

    # Adjust layout and save the plot
    plt.tight_layout(pad=0.3)
    plt.savefig(os.path.join(plot_dir, "n32_modes.pdf"), dpi=300, bbox_inches='tight')

print("Bar plot comparing cold and warm starts for base, e2e, h2h, prins, and prins_tcp saved to the plots directory.")