import json
import matplotlib.pyplot as plt
import numpy as np

# Load the JSON data
file_path = "../packet_length_analysis.json"
with open(file_path, "r") as file:
    data = json.load(file)
single_column_width = 3.5  # inches
double_column_width = 7.0  # inches
font_size = 15  # Adjust font size for readability in papers
plt.rcParams.update({'font.size': font_size})

plt.rc('text', usetex=True)
plt.rc('font', family='serif')

# Function to create a grouped bar plot
def plot_grouped_bar_packet_lengths(data):
    sizes = ["small", "middle", "large"]
    tls_protocols = ["E2E_TLS", "H2H_TLS"]
    prins_protocol = "PRINS"
    categories_prins = ["ciphertext", "even", "aad"]

    # Prepare data for the grouped bar plot
    num_data_points = len(data["E2E_TLS"]["small"]["even"]["packet_length"])
    bar_width = 0.1  # Width of each bar
    x_positions = np.arange(len(sizes)) * 2  # Positions for the main groups (small, middle, large)

    # Initialize the plot with a smaller figure size for IEEE double-column
    fig, ax = plt.subplots(figsize=(double_column_width, 3.5))  # Create a figure and axis

    # Define colors for the five options
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
    labels = [
        "E2E_TLS (even)",
        "H2H_TLS (even)",
        "PRINS (ciphertext)",
        "PRINS (even)",
        "PRINS (aad)"
    ]
    subgroup_labels = ["a", "a", "a", "b", "b", "b", "c", "c", "c"]  # Labels for the subgroups

    # Iterate over each data point (subgroup)
    for i in range(num_data_points):
        offset = (i - (num_data_points - 1) / 2) * bar_width * 6  # Center subgroups within each main group
        for j, size in enumerate(sizes):
            # Collect values for the five options
            values = [
                data["E2E_TLS"][size]["even"]["packet_length"][i],
                data["H2H_TLS"][size]["even"]["packet_length"][i],
                data["PRINS"][size]["ciphertext"]["packet_length"][i],
                data["PRINS"][size]["even"]["packet_length"][i],
                data["PRINS"][size]["aad"]["packet_length"][i],
            ]
            # Plot bars for the current subgroup
            for k, value in enumerate(values):
                ax.bar(
                    x_positions[j] + offset + k * bar_width,
                    value,
                    bar_width,
                    color=colors[k],
                    edgecolor='black',
                    linewidth=0.1,
                    label=labels[k] if i == 0 and j == 0 else None,  # Add legend only once
                )

    x_positions_subgroup = []
    for i in range(num_data_points):
        offset = (i - (num_data_points - 1) / 2) * bar_width * 6 + bar_width * 2
        for j in range(len(sizes)):
            x_positions_subgroup.append(x_positions[j] + offset) # + i * bar_width)
            # print(x_positions_subgroup)

    # Add labels, legend, and title with increased font sizes
    ax.set_xticks(
        x_positions + 2 * bar_width,
        sizes,
        fontsize=font_size
    )
    
    ax.set_xlabel("Message Size", fontsize=font_size, labelpad=1)
    ax.set_ylabel("Packet Length [Byte]", fontsize=font_size, labelpad=3)
    # ax.set_title("Grouped Bar Plot of Packet Lengths", fontsize=14)
    ax.tick_params(axis='x', pad=13)
    ax.tick_params(axis='y', pad=1)
    ax.legend(loc="upper left", fontsize=font_size-1)
    # ax.grid(axis='y', linestyle='--', alpha=0.7)  # Add horizontal grid lines
    ax.grid(axis='y', alpha=0.7)  # Add horizontal grid lines
    
    ax2 = ax.secondary_xaxis('bottom')  # Create a secondary x-axis
    ax2.set_xlim(ax.get_xlim())  # Align with the primary x-axis
    ax2.set_xticks(x_positions_subgroup)  # Adjust positions for subgroups
    ax2.set_xticklabels(subgroup_labels, fontsize=font_size-1)
    ax2.tick_params(axis='x', which='both', length=0, pad=5)  # Hide tick marks for the second x-axis
    plt.tight_layout(pad=0.3)
    # plt.tight_layout()

    # Save the plot
    plt.savefig("plots/packet_lengths.pdf")
    # plt.show()

# Generate the grouped bar plot
plot_grouped_bar_packet_lengths(data)

### first tests for two x-axes