class Permutation:
    def __init__(self, mapping):
        self.length = len(mapping)

        assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
        self.mapping = list(mapping)

    def __call__(self, *args, **kwargs):
        idx, *_ = args
        assert idx in range(self.length)
        return self.mapping[idx]

    def __mul__(self, other):
        ans = []

        for i in range(self.length):
            ans.append(self(other(i)))

        return Permutation(ans)
    def __truediv__(self, other):
        ans = [0] * self.length

        for i in range(self.length):
            ans[self.mapping[i]] = other.mapping[i]
        return Permutation(ans)

    def __pow__(self, power, modulo=None):
        ans = Permutation.identity(self.length)
        ctr = self

        while power > 0:
            if power % 2 == 1:
                ans *= ctr
            ctr *= ctr
            power //= 2

        return ans

    def __str__(self):
        return str(self.mapping)

    def identity(length):
        return Permutation(range(length))


perm1 = Permutation([1, 0, 2])
perm2 = Permutation([0, 2, 1])

result = perm1 * perm2
print("result = ", result)  

test = result / perm2 # == perm1
print("test = ",test.mapping)
print("perm1 = ", perm1.mapping)