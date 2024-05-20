from sympy import symbols, solve

x, y, z = symbols('x y z')

eq1 = 2*x + 3*y - 4*z - 5
eq2 = x - y + z - 1 
eq3 = 3*x + 2*y - z - 7

solutions = solve([eq1, eq2, eq3], [x, y, z])
print(solutions[x])