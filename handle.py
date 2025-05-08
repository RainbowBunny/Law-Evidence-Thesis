time = [[] for _ in range(2)]

for i in range(10):
  data = open(f"openPIA/data{i}.txt", "r").readlines()
  time[0].append(eval(data[6]))
  time[1].append(eval(data[7]))


for i in range(2):
  print(sum(time[i]) / len(time[i]))

"""
import matplotlib.pyplot as plt
import numpy as np

time = [[] for _ in range(3)]

data = open(f"case/time.txt", "r").readlines()
for j in range(len(data)):
  x, y = data[j].split(" ")
  time[j % 2].append((eval(x), eval(y)))

def plot_with_best_fit(ax, data, title):
    x_vals = np.array([x for x, y in data])
    y_vals = np.array([y for x, y in data])

    m, b = np.polyfit(x_vals, y_vals, 1)
    best_fit_line = m * x_vals + b

    ax.scatter(x_vals, y_vals, color='blue', label='Data Points')
    ax.plot(x_vals, best_fit_line, color='red')
    ax.set_title(title)
    ax.set_xlabel('x')
    ax.set_ylabel('y')
    ax.legend()
    ax.grid(True)

# Create subplots side by side
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

plot_with_best_fit(ax1, time[0], 'Provide')
plot_with_best_fit(ax2, time[1], 'Upload')

plt.tight_layout()
plt.show()
"""

print(a,)