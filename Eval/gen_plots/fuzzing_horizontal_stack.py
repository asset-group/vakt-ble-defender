import matplotlib.pyplot as plt
import numpy as np

time_intervals = ['15m', '30m', '45m', '1h']

fuzzer = {
    'Successful connections': [269, 331, 301, 308]
}

defender = {
    'Successful connections': [265, 331, 295, 303],
    'Anomalies': {
        'Malformed': [172, 202, 168, 168],
        'Flooding': [68, 125, 101, 101],
        'Out of order': [22, 2, 26, 24]
    }
}

colors = ['#66c2a5', '#fc8d62', '#8da0cb', '#e78ac3', '#fca3b3']

successful_conn_values_fuzzer = np.cumsum(fuzzer['Successful connections'])
malformed_values = np.cumsum(defender['Anomalies']['Malformed'])
flooding_values = np.cumsum(defender['Anomalies']['Flooding'])
out_of_order_values = np.cumsum(defender['Anomalies']['Out of order'])

# Calculate the last value
last_values = successful_conn_values_fuzzer - (malformed_values + flooding_values + out_of_order_values)
plt.rc('pdf', fonttype=42)
#fig, ax = plt.subplots()
fig, ax = plt.subplots(figsize=(10, 4))  # Adjust the width and height as needed
# Calculate y-axis positions for the bars (offset for centering)
y_positions = np.arange(len(time_intervals))

# Plot successful connections for fuzzer
ax.barh(y_positions, successful_conn_values_fuzzer, color=colors[0], edgecolor='black', label='False Negatives')

# Plot anomalies stacked on top of successful connections for defender
ax.barh(y_positions, malformed_values, color=colors[1], edgecolor='black', label='Invalid')
ax.barh(y_positions, flooding_values, left=malformed_values, color=colors[2], edgecolor='black', label='Flooding')
ax.barh(y_positions, out_of_order_values, left=malformed_values + flooding_values, color=colors[3], edgecolor='black', label='Out of Order')
ax.barh(y_positions, 0, color='white',label='15 min: 172/68/22/7')
ax.barh(y_positions, 0, color='white',label='30 min: 374/193/22/24/9')
ax.barh(y_positions, 0, color='white',label='55 min: 542/294/50/15')
ax.barh(y_positions, 0, color='white',label='1 hr:  710/395/74/30')


# Add values below labels
#for i, time_interval in enumerate(time_intervals):
#    values_text = f"{malformed_values[i]}/{flooding_values[i]}/{out_of_order_values[i]}/{min(last_values[i], successful_conn_values_fuzzer[i])}"
#    ax.text(min(last_values[i], successful_conn_values_fuzzer[i]) + 10 , i, values_text, va='center', fontsize=10, color='black')

# Set y-axis tick positions and labels
ax.set_yticks(y_positions)
ax.set_yticklabels(time_intervals)

# Add a legend
ax.legend(loc='lower right',fontsize='10.5')

# Add labels and title
ax.set_xlabel('# of attacks', fontsize=21)
ax.set_ylabel('Time Intervals', fontsize=21)
ax.tick_params(axis='x', which='major', labelsize=18)  # Adjust the fontsize as needed
ax.tick_params(axis='y', which='major', labelsize=18)  # Adjust the fontsize as needed


# Set the grid to be drawn behind other plot elements
ax.set_axisbelow(True)

# Add grid lines aligned with the bars
ax.grid(axis='x', linestyle='--', color='black', alpha=0.7)

plt.tight_layout()
#plt.savefig('cummulative_fuzzing_horizontal.pdf')  
plt.show()
