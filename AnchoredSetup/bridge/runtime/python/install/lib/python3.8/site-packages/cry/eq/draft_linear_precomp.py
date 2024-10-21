from cry.sagestuff import matrix, vector, GF, matrix, Permutation

F2 = GF(2)


class AffineSystem:
    def __init__(self, oracle, n_in, field=F2):
        self.field = field
        self.n_in = int(n_in)

        zero = vector(field, oracle([0] * n_in))
        self.n_out = len(zero)
        cols = []
        for i in range(n_in):
            x = [0] * n_in
            x[i] = 1
            y = vector(field, oracle(x)) - zero
            cols.append(y)

        self.matrix = matrix(field, cols).transpose()
        self.matrix_rk = None

        self.rank = self.matrix.rank()
        self.kernel_dimension = self.matrix.ncols() - self.rank
        self.permx = perm_complete(
            self.matrix.pivots(),
            self.matrix.ncols(),
        )
        self.permy = perm_complete(
            self.matrix.pivot_rows(),
            self.matrix.nrows(),
        )

        m = self.matrix
        m = matrix(m[i] for i in self.permy).transpose()
        m = matrix(m[i] for i in self.permx).transpose()

        assert m.pivots() == tuple(range(self.rank))
        assert m.pivots() == tuple(range(self.rank))

        self.P, self.L, self.U = m.LU()
        self.P = self.P.change_ring(self.field)
        self.Pi = ~self.P.change_ring(self.field)
        self.L = self.L
        self.Li = ~self.L  # by hand faster or not? lower-triangular
        self.u = self.U[:self.rank, :self.rank]
        self.ui = ~self.u
        self.u_free = self.u[:, self.rank:]

    def solve_sage(self, target, all=False):
        x = self.matrix.solve_right(vector(self.field, target))
        # y = x
        # y = perm_to_matrix(self.permx) * y
        # y = self.U * y
        # y = self.L * y
        # y = self.P * y
        # y = ~perm_to_matrix(self.permy) * y
        # print(tuple(y))
        # print(tuple(target))
        # assert tuple(y) == tuple(target)
        if not all:
            return x
        if self.matrix_rk is None:
            self.matrix_rk = self.matrix.right_kernel()
        for z in self.matrix_rk:
            yield z + x

    def solve(self, target, all=False):
        assert len(self.field) == 2, "Gray code is implemented only for GF(2)"
        y = target
        y = perm_apply(self.permy, y)
        y = vector(self.field, y)
        y = self.Pi * y
        y = self.Li * y
        y = y[:self.rank]

        mask = 0
        free = [0] * self.kernel_dimension
        for i in range(1 << self.kernel_dimension):
            x = self.ui * y
            x = list(x) + free
            x = perm_apply(self.permx, x, inverse=True)
            assert self.matrix * vector(GF(2), x) == vector(GF(2), target)
            if not all:
                return x
            yield x

            if i < (1 << self.kernel_dimension) - 1:
                # use Gray code to add only one vector
                prev = mask
                mask = (i + 1) ^ ((i + 1) >> 1)
                index = self.kernel_dimension - int(prev ^ mask).bit_length()

                free[index] ^= 1
                y += self.u_free[index]

if 0:
    from cry.sagestuff import *
    while True:
        m = random_matrix(GF(2), 10, 10)
        if m.rank() <= 8:
            break
    print(m.rank())

    def oracle(x):
        return m * vector(GF(2), x)

    A = AffineSystem(oracle, m.ncols())
    x = random_vector(GF(2), m.ncols())
    y = A.matrix * x
    A.solve_sage(y)
    for x in A.solve(y):
        pass
