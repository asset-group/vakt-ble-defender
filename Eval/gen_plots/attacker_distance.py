import matplotlib.pyplot as plt


distances = ['~2cm','30 cm', '1 m', '5 m', '10 m', '15m']
success_rates = [70, 90, 100, 100, 100, 90] 


cake_colors = ['#6495ED', '#6495ED', '#6495ED', '#6495ED','#6495ED','#6495ED']

# Create a figure and axis objects
fig, ax = plt.subplots(figsize=(10, 4))


edge_colors = ['#000000'] * len(distances)
bars = ax.barh(distances, success_rates, edgecolor=edge_colors, linewidth=1.5, height=0.6)


for bar, color in zip(bars, cake_colors):
    bar.set_facecolor(color)


plt.xlabel('Success Rate [%]', fontsize=21)
plt.ylabel('Distance', fontsize=21)



plt.xlim(0, 110)
plt.xticks(range(0, 110, 10),fontsize=19)
plt.yticks(fontsize=19)


plt.grid(axis='x', linestyle='--', alpha=0.5)
plt.rcParams.update({'font.size': 10})
plt.rc('pdf', fonttype=42)

for i, rate in enumerate(success_rates):
    ax.text(rate + 0.6, i, f"{int(rate/10)}/10", va='center', fontsize=13, fontweight='bold', color='black')


plt.tight_layout()

# Save the plot as a PDF file
plt.savefig('attacker_distance_success_rate_horizontal.pdf', format='pdf')


plt.show()
