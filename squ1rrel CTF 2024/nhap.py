from itertools import combinations

def flatten_tuple(nested_tuple):
    flattened_tuple = tuple(item for sublist in nested_tuple for item in sublist)
    return flattened_tuple

def generate_triplets(tuple_list):
    triplets = []
    for triplet_combo in combinations(tuple_list, 3):
        triplets.append(flatten_tuple(triplet_combo))
    return triplets

# Example usage:
tuple_lists = [[(1, 2, 3), (4, 5, 6), (7, 8, 9), (10, 11, 12), (13, 14, 15)],
    [(16, 17, 18), (19, 20, 21), (22, 23, 24), (25, 26, 27), (28, 29, 30)],
    [(31, 32, 33), (34, 35, 36), (37, 38, 39), (40, 41, 42), (43, 44, 45)],
    [(46, 47, 48), (49, 50, 51), (52, 53, 54), (55, 56, 57), (58, 59, 60)]]
for tuple_list in tuple_lists:
    triplets = generate_triplets(tuple_list)
    for triplet_combo in triplets:
        print(triplet_combo, ",")