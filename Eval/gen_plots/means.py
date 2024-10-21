with open('overhead_bledefender.txt', 'r') as file:
    numbers_str = file.read()

# Split the numbers into a list
numbers_list = [int(num) for num in numbers_str.split('\n') if num]

# Calculate the mean of all the numbers
mean_of_all_numbers = sum(numbers_list) / len(numbers_list)

# Calculate the mean for each group of 10 numbers
num_groups = len(numbers_list) // 10
means = [sum(numbers_list[i*10:(i+1)*10]) / 10 for i in range(num_groups)]

# Print the mean of all the numbers and the list of means for each group of 10
print("Mean of all numbers:", mean_of_all_numbers)
print("Means of each group of 10 numbers:", means)
