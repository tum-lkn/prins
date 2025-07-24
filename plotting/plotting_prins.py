import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import pandas as pd

# Define the paths and parameters
results_dir = "../results"
plot_dir = "plots"
mode = "prins"  # Focus only on prins mode
sizes = ["small", "middle", "large"]
types = ["ciphertext", "even", "aad"]
lower_percentile = 1
upper_percentile = 99

plt.rc('text', usetex=True)
plt.rc('font', family='serif')

# Adjust figure settings for double-column format
single_column_width = 3.5  # inches
double_column_width = 7.0  # inches
font_size = 15  # Adjust font size for readability in papers
# Set up the figure style
plt.rcParams.update({'font.size': font_size})

def read_data_file(filepath):
    """Read time durations from a data file"""
    try:
        with open(filepath, 'r') as f:
            data = [float(line.strip()) for line in f if line.strip()]
        return data
    except FileNotFoundError:
        print(f"Warning: File {filepath} not found")
        return []

def filter_outliers(data, lower_percentile=lower_percentile, upper_percentile=upper_percentile):
    """Filter out data outside the specified percentile range"""
    if not data:
        return []
    lower = np.percentile(data, lower_percentile)
    upper = np.percentile(data, upper_percentile)
    return [x for x in data if lower <= x <= upper]

# Collect all prins data
prins_data = {}
prins_data_filtered = {}  # For storing data with outliers removed

for size in sizes:
    prins_data[size] = {}
    prins_data_filtered[size] = {}
    for type_ in types:
        filename = f"{mode}_{size}_{type_}_warm.txt"
        filepath = os.path.join(results_dir, filename)
        raw_data = read_data_file(filepath)
        prins_data[size][type_] = raw_data
        # Filter outliers - keep only 5th to 9lower_percentileth percentile
        prins_data_filtered[size][type_] = filter_outliers(raw_data, lower_percentile, upper_percentile)

plt.figure(figsize=(12, 8))
all_data = []
labels = []

for size in sizes:
    for type_ in types:
        data = prins_data_filtered[size][type_]
        if data:
            all_data.append(data)
            labels.append(f"{size}_{type_}")

# Prepare data for dataframe
flat_data = []
for size in sizes:
    for type_ in types:
        data = prins_data_filtered[size][type_]
        if data:
            mean_value = np.mean(data)
            print(f"Mean value for {size} {type_}: {mean_value:.2f}")
            for value in data:
                flat_data.append((size, type_, value))

if flat_data:
    df = pd.DataFrame(flat_data, columns=['Size', 'Type', 'Duration'])
        
    # 3.2 Compare different types
    plt.figure(figsize=(double_column_width, 3.5))  # Double-column width
    sns.violinplot(x='Type', y='Duration', hue='Size', data=df, palette="Set1", split=False, density_norm="width")
    # sns.barplot(x='Type', y='Duration', hue='Size', data=df, palette="Set1",errorbar="se", capsize=0.1, edgecolor="k")
    # plt.title(f"Duration Distribution by Type ({lower_percentile}-{upper_percentile} percentile)", fontsize=font_size)
    plt.legend(title="Message Size", fontsize=font_size - 2, loc='lower right', ncol=3)
    # plt.grid(axis='y', linestyle='--', alpha=0.7)  # Add horizontal grid lines
    plt.grid(axis='y', alpha=0.7)  # Add horizontal grid lines
    plt.ylabel("Latency [ms]", fontsize=font_size)
    plt.xlabel("Split", fontsize=font_size)
    plt.tight_layout(pad=0.3)
    plt.savefig(os.path.join(plot_dir, "prins_comparison.pdf"), dpi=300)


print(f"Prins mode analysis complete! Visualizations saved to the plots directory.")